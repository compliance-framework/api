package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RiskEvidenceWorker handles processing evidence failure and creating risks
type RiskEvidenceWorker struct {
	db     *gorm.DB
	logger *zap.SugaredLogger
}

// NewRiskEvidenceWorker creates a new RiskEvidenceWorker
func NewRiskEvidenceWorker(db *gorm.DB, logger *zap.SugaredLogger) *RiskEvidenceWorker {
	return &RiskEvidenceWorker{
		db:     db,
		logger: logger,
	}
}

// Work is the River work function for processing evidence failure and creating risks
func (w *RiskEvidenceWorker) Work(ctx context.Context, job *river.Job[RiskProcessEvidenceFailureArgs]) error {
	args := job.Args

	w.logger.Infow("Processing risk evidence failure job",
		"evidence_id", args.EvidenceID,
		"evidence_end", args.EvidenceEnd,
		"status", args.Status,
	)

	// Step 4: Implement Risk Resolver Algorithm

	// 1. Load Data: Load the Evidence by ID (including labels, violations/props, and linked subjects)
	evidence, err := w.loadEvidenceWithRelations(ctx, args.EvidenceID)
	if err != nil {
		w.logger.Errorw("Failed to load evidence", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	// 2. Template Matching: Match the applicable EvidenceTemplate using selector_labels
	matchedTemplates, err := w.matchEvidenceTemplates(ctx, evidence.Labels)
	if err != nil {
		w.logger.Errorw("Failed to match evidence templates", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	if len(matchedTemplates) == 0 {
		w.logger.Infow("No matching evidence templates found", "evidence_id", args.EvidenceID)
		return nil
	}

	// 3. Risk Templates: Load the linked RiskTemplate set from the matched EvidenceTemplate
	riskTemplates, err := w.loadRiskTemplates(ctx, matchedTemplates)
	if err != nil {
		w.logger.Errorw("Failed to load risk templates", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	// 4. Violation Filtering: Filter the risk templates by checking the fired violation.id against risk_template.violation_ids
	filteredRiskTemplates, err := w.filterRiskTemplatesByViolations(ctx, riskTemplates, evidence.Props)
	if err != nil {
		w.logger.Errorw("Failed to filter risk templates by violations", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	// 5. Risk Creation/Update: For each candidate RiskTemplate, create one risk per SSP.
	// Collect per-template errors so River can retry the whole job if any template fails.
	var errs []error
	for _, riskTemplate := range filteredRiskTemplates {
		if err := w.createOrUpdateRisksForSSPs(ctx, riskTemplate, evidence); err != nil {
			w.logger.Errorw("Failed to create or update risks for SSPs",
				"error", err,
				"evidence_id", args.EvidenceID,
				"risk_template_id", riskTemplate.ID)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	w.logger.Infow("Risk evidence failure job processed successfully",
		"evidence_id", args.EvidenceID,
		"matched_templates", len(matchedTemplates),
		"risk_templates", len(filteredRiskTemplates),
	)

	return nil
}

// RiskEvidenceWorker helper methods

// loadEvidenceWithRelations loads evidence with all required relations for risk processing
func (w *RiskEvidenceWorker) loadEvidenceWithRelations(ctx context.Context, evidenceID uuid.UUID) (*relational.Evidence, error) {
	var evidence relational.Evidence

	err := w.db.WithContext(ctx).
		Preload("Labels").
		Preload("Subjects").
		Preload("Subjects.IncludeSubjects").
		Preload("Components").
		Preload("InventoryItems").
		Where("id = ?", evidenceID).
		First(&evidence).Error

	if err != nil {
		return nil, fmt.Errorf("failed to load evidence %s: %w", evidenceID, err)
	}

	return &evidence, nil
}

// matchEvidenceTemplates matches evidence labels against evidence template selector labels
func (w *RiskEvidenceWorker) matchEvidenceTemplates(ctx context.Context, evidenceLabels []relational.Labels) ([]templates.EvidenceTemplate, error) {
	// Convert evidence labels to a map for easier lookup
	evidenceLabelMap := make(map[string]string)
	for _, label := range evidenceLabels {
		evidenceLabelMap[label.Name] = label.Value
	}

	// Get all active evidence templates. Cap at 200 (consistent with the templates service scan
	// limit) to avoid unbounded memory usage. Log a warning if the limit is reached so operators
	// are alerted before templates are silently dropped.
	const maxTemplateScan = 200
	var allTemplates []templates.EvidenceTemplate
	err := w.db.WithContext(ctx).
		Preload("SelectorLabels").
		Where("is_active = ?", true).
		Order("id ASC").
		Limit(maxTemplateScan).
		Find(&allTemplates).Error

	if err != nil {
		return nil, fmt.Errorf("failed to load evidence templates: %w", err)
	}

	if len(allTemplates) == maxTemplateScan {
		w.logger.Warnw("Evidence template scan reached the limit; some templates may not have been evaluated",
			"limit", maxTemplateScan)
	}

	var matchedTemplates []templates.EvidenceTemplate

	for _, template := range allTemplates {
		// Check if all selector labels match the evidence labels
		if w.templateMatchesLabels(template, evidenceLabelMap) {
			matchedTemplates = append(matchedTemplates, template)
		}
	}

	return matchedTemplates, nil
}

// templateMatchesLabels checks if a template's selector labels all match the evidence labels.
// A template with zero selector labels acts as a wildcard and matches ALL evidence,
// regardless of labels. This is intentional but should be used carefully — wildcard
// templates will trigger risk creation for every not-satisfied evidence record.
func (w *RiskEvidenceWorker) templateMatchesLabels(template templates.EvidenceTemplate, evidenceLabels map[string]string) bool {
	for _, selectorLabel := range template.SelectorLabels {
		if evidenceValue, exists := evidenceLabels[selectorLabel.Key]; !exists || evidenceValue != selectorLabel.Value {
			return false
		}
	}
	return true
}

// loadRiskTemplates loads risk templates linked to the matched evidence templates
func (w *RiskEvidenceWorker) loadRiskTemplates(ctx context.Context, evidenceTemplates []templates.EvidenceTemplate) ([]templates.RiskTemplate, error) {
	if len(evidenceTemplates) == 0 {
		return nil, nil
	}

	// Extract evidence template IDs
	evidenceTemplateIDs := make([]uuid.UUID, len(evidenceTemplates))
	for i, template := range evidenceTemplates {
		evidenceTemplateIDs[i] = *template.ID
	}

	// Get evidence template risk template relationships
	var relationships []templates.EvidenceTemplateRiskTemplate
	err := w.db.WithContext(ctx).
		Where("evidence_template_id IN ?", evidenceTemplateIDs).
		Find(&relationships).Error

	if err != nil {
		return nil, fmt.Errorf("failed to load evidence template risk template relationships: %w", err)
	}

	if len(relationships) == 0 {
		return nil, nil
	}

	// Extract risk template IDs
	riskTemplateIDs := make([]uuid.UUID, len(relationships))
	for i, rel := range relationships {
		riskTemplateIDs[i] = rel.RiskTemplateID
	}

	// Load risk templates
	var riskTemplates []templates.RiskTemplate
	err = w.db.WithContext(ctx).
		Where("id IN ? AND is_active = ?", riskTemplateIDs, true).
		Find(&riskTemplates).Error

	if err != nil {
		return nil, fmt.Errorf("failed to load risk templates: %w", err)
	}

	return riskTemplates, nil
}

// filterRiskTemplatesByViolations filters risk templates based on violation IDs in evidence props
func (w *RiskEvidenceWorker) filterRiskTemplatesByViolations(ctx context.Context, riskTemplates []templates.RiskTemplate, evidenceProps []relational.Prop) ([]templates.RiskTemplate, error) {
	// Extract violation IDs from evidence props
	violationIDs := w.extractViolationIDs(evidenceProps)

	var filteredTemplates []templates.RiskTemplate

	for _, template := range riskTemplates {
		// If risk template has no violation IDs filter, it matches any violation
		if len(template.ViolationIDs) == 0 {
			filteredTemplates = append(filteredTemplates, template)
			continue
		}

		// Check if any violation ID in evidence matches the template's violation IDs
		if w.violationMatches(template.ViolationIDs, violationIDs) {
			filteredTemplates = append(filteredTemplates, template)
		}
	}

	return filteredTemplates, nil
}

// extractViolationIDs extracts violation IDs from evidence props
func (w *RiskEvidenceWorker) extractViolationIDs(props []relational.Prop) []string {
	var violationIDs []string

	for _, prop := range props {
		// Look for props with name exactly "violation_id"
		if prop.Name == "violation_id" && prop.Value != "" {
			violationIDs = append(violationIDs, prop.Value)
		}
	}

	return violationIDs
}

// violationMatches checks if any evidence violation ID matches the template's violation IDs.
// Uses a set lookup (O(N+M)) rather than nested loops (O(N*M)).
func (w *RiskEvidenceWorker) violationMatches(templateViolationIDs, evidenceViolationIDs []string) bool {
	if len(templateViolationIDs) == 0 || len(evidenceViolationIDs) == 0 {
		return false
	}

	// Build a set from the shorter slice to minimise allocations.
	shorter, longer := templateViolationIDs, evidenceViolationIDs
	if len(evidenceViolationIDs) < len(templateViolationIDs) {
		shorter, longer = evidenceViolationIDs, templateViolationIDs
	}

	set := make(map[string]struct{}, len(shorter))
	for _, id := range shorter {
		set[id] = struct{}{}
	}
	for _, id := range longer {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}

// createOrUpdateRisksForSSPs creates or updates risks for each SSP associated with the evidence
func (w *RiskEvidenceWorker) createOrUpdateRisksForSSPs(ctx context.Context, riskTemplate templates.RiskTemplate, evidence *relational.Evidence) error {
	// TODO: we are using Evidence.Components as a proxy for now, but in reality this should use SubjectTemplates to find the appropriate SystemComponents -> SSPIds

	// Get unique SSP IDs from evidence components
	sspIDs, err := w.extractSSPIDsFromComponents(ctx, evidence.Components)
	if err != nil {
		return fmt.Errorf("failed to extract SSP IDs from components: %w", err)
	}
	// Create/update one risk per SSP
	// If no SSPIDs are valid, no risks are needed
	var errs []error
	for _, sspID := range sspIDs {
		// Compute dedupe key: ssp_id + risk_template_id + sorted subject identity keys
		dedupeKey := w.computeDedupeKeyForSSP(riskTemplate, evidence, sspID)

		// Look for existing active risk with this dedupe key
		var existingRisk risks.Risk
		err := w.db.WithContext(ctx).
			Where("dedupe_key = ? AND status != ?", dedupeKey, risks.RiskStatusClosed).
			First(&existingRisk).Error

		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			errs = append(errs, fmt.Errorf("failed to check for existing risk: %w", err))
			continue
		}

		if err == nil {
			// Existing risk found - update it
			err = w.updateExistingRisk(ctx, &existingRisk, riskTemplate, evidence)
		} else {
			// No existing risk - create new one
			err = w.createNewRiskForSSP(ctx, riskTemplate, evidence, sspID, dedupeKey)
		}

		if err != nil {
			w.logger.Errorw("Failed to create or update risk for SSP",
				"error", err,
				"evidence_id", evidence.ID,
				"risk_template_id", riskTemplate.ID,
				"ssp_id", sspID)
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// extractSSPIDsFromComponents extracts unique SSP IDs from evidence components.
// Returns an error on DB failure so the caller (and River job) can retry rather than
// silently producing no risks.
func (w *RiskEvidenceWorker) extractSSPIDsFromComponents(ctx context.Context, components []relational.SystemComponent) ([]uuid.UUID, error) {
	if len(components) == 0 {
		return []uuid.UUID{}, nil
	}

	// Extract unique SystemImplementation IDs from components
	implIDs := make([]uuid.UUID, 0, len(components))
	seenImplIDs := make(map[uuid.UUID]bool)

	for _, component := range components {
		if component.SystemImplementationId != uuid.Nil && !seenImplIDs[component.SystemImplementationId] {
			implIDs = append(implIDs, component.SystemImplementationId)
			seenImplIDs[component.SystemImplementationId] = true
		}
	}

	if len(implIDs) == 0 {
		return []uuid.UUID{}, nil
	}

	// Load SystemImplementations to get SSP IDs
	var implementations []relational.SystemImplementation
	if err := w.db.WithContext(ctx).
		Where("id IN ?", implIDs).
		Find(&implementations).Error; err != nil {
		return nil, fmt.Errorf("failed to load system implementations for impl IDs %v: %w", implIDs, err)
	}

	// Extract unique SSP IDs
	sspIDs := make([]uuid.UUID, 0, len(implementations))
	seenSSPIDs := make(map[uuid.UUID]bool)

	for _, impl := range implementations {
		if impl.SystemSecurityPlanId != uuid.Nil && !seenSSPIDs[impl.SystemSecurityPlanId] {
			sspIDs = append(sspIDs, impl.SystemSecurityPlanId)
			seenSSPIDs[impl.SystemSecurityPlanId] = true
		}
	}

	return sspIDs, nil
}

// computeDedupeKeyForSSP computes the dedupe key for a risk.
// The key uses sorted, stable subject identity keys so that two separate agents reporting the
// same violation for the same subjects map to the same risk, enabling correct deduplication.
// We prefer SubjectUUID from IncludeSubjects (the stable entity reference) and fall back to
// the AssessmentSubject row ID only when IncludeSubjects is empty.
// Format: ssp_id:risk_template_id:sorted_subject_identity_keys
func (w *RiskEvidenceWorker) computeDedupeKeyForSSP(riskTemplate templates.RiskTemplate, evidence *relational.Evidence, sspID uuid.UUID) string {
	subjectKeys := make([]string, 0, len(evidence.Subjects))
	for _, subject := range evidence.Subjects {
		hasStableKey := false
		for _, inc := range subject.IncludeSubjects {
			if inc.SubjectUUID != uuid.Nil {
				subjectKeys = append(subjectKeys, inc.SubjectUUID.String())
				hasStableKey = true
			}
		}
		// Fall back to the row ID when no IncludeSubjects are populated.
		if !hasStableKey && subject.ID != nil {
			subjectKeys = append(subjectKeys, subject.ID.String())
		}
	}
	sort.Strings(subjectKeys)
	return fmt.Sprintf("%s:%s:%s", sspID.String(), riskTemplate.ID.String(), strings.Join(subjectKeys, ","))
}

// updateExistingRisk updates an existing risk with new evidence
func (w *RiskEvidenceWorker) updateExistingRisk(ctx context.Context, existingRisk *risks.Risk, riskTemplate templates.RiskTemplate, evidence *relational.Evidence) error {
	now := time.Now().UTC()

	// Capture previous value before mutation so the event payload is accurate.
	previousLastSeen := existingRisk.LastSeenAt

	// Update last seen time
	existingRisk.LastSeenAt = now

	// Save the updated risk
	err := w.db.WithContext(ctx).Save(existingRisk).Error
	if err != nil {
		return fmt.Errorf("failed to update existing risk: %w", err)
	}

	// Re-create all risk links (evidence, subjects, components) for this new piece of evidence.
	// createRiskLinks is idempotent via OnConflict{DoNothing}, so this is safe for existing risks
	// and also keeps subject/component associations up to date as new evidence arrives.
	var errs []error
	if err := w.createRiskLinks(ctx, w.db, *existingRisk.ID, evidence); err != nil {
		w.logger.Errorw("Failed to create/update risk links", "error", err, "risk_id", existingRisk.ID, "evidence_id", evidence.ID)
		errs = append(errs, fmt.Errorf("failed to create risk links: %w", err))
	}

	// Emit a risk_event(last_seen) using the typed constant
	if err := w.emitRiskEvent(ctx, *existingRisk.ID, string(risks.RiskEventTypeLastSeen), map[string]interface{}{
		"evidence_id":        evidence.ID,
		"previous_last_seen": previousLastSeen,
		"new_last_seen":      now,
	}); err != nil {
		w.logger.Errorw("Failed to emit risk event", "error", err, "risk_id", existingRisk.ID)
		errs = append(errs, fmt.Errorf("failed to emit risk event: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	w.logger.Infow("Updated existing risk",
		"risk_id", existingRisk.ID,
		"evidence_id", evidence.ID,
		"dedupe_key", existingRisk.DedupeKey,
	)

	return nil
}

// createNewRiskForSSP creates a new risk based on the template, evidence, and SSP.
// The risk row and all its links are created inside a single transaction so that a
// link failure cannot leave an orphaned risk with no evidence.
func (w *RiskEvidenceWorker) createNewRiskForSSP(ctx context.Context, riskTemplate templates.RiskTemplate, evidence *relational.Evidence, sspID uuid.UUID, dedupeKey string) error {
	now := time.Now().UTC()

	newRisk := risks.Risk{
		Title:          riskTemplate.Title,
		Description:    riskTemplate.Statement,
		Status:         string(risks.RiskStatusOpen),
		SSPID:          sspID,
		RiskTemplateID: riskTemplate.ID,
		SourceType:     string(risks.RiskSourceTypeEvidenceAuto),
		DedupeKey:      dedupeKey,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}

	// Set likelihood and impact from template hints if available
	if riskTemplate.LikelihoodHint != nil {
		newRisk.Likelihood = riskTemplate.LikelihoodHint
	}
	if riskTemplate.ImpactHint != nil {
		newRisk.Impact = riskTemplate.ImpactHint
	}

	err := w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&newRisk).Error; err != nil {
			return fmt.Errorf("failed to create new risk: %w", err)
		}
		return w.createRiskLinks(ctx, tx, *newRisk.ID, evidence)
	})
	if err != nil {
		return err
	}

	// Emit a risk_event(created) using the typed constant
	if err := w.emitRiskEvent(ctx, *newRisk.ID, string(risks.RiskEventTypeCreated), map[string]interface{}{
		"evidence_id": evidence.ID,
		"template_id": riskTemplate.ID,
		"dedupe_key":  dedupeKey,
		"ssp_id":      sspID,
	}); err != nil {
		w.logger.Warnw("Failed to emit risk event", "error", err, "risk_id", newRisk.ID)
	}

	w.logger.Infow("Created new risk",
		"risk_id", newRisk.ID,
		"evidence_id", evidence.ID,
		"risk_template_id", riskTemplate.ID,
		"ssp_id", sspID,
		"dedupe_key", dedupeKey,
	)

	return nil
}

// linkEvidenceToRisk creates a link between a risk and evidence.
// Uses OnConflict{DoNothing} so that retries after transient failures are idempotent.
func (w *RiskEvidenceWorker) linkEvidenceToRisk(ctx context.Context, riskID, evidenceID uuid.UUID) error {
	link := &risks.RiskEvidenceLink{
		RiskID:     riskID,
		EvidenceID: evidenceID,
		CreatedAt:  time.Now().UTC(),
	}

	return w.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(link).Error
}

// createRiskLinks creates all necessary links for a risk (evidence, subject, component, control).
// Accepts a *gorm.DB so the caller can pass a transaction.
// Uses OnConflict{DoNothing} throughout so retries are idempotent.
func (w *RiskEvidenceWorker) createRiskLinks(ctx context.Context, db *gorm.DB, riskID uuid.UUID, evidence *relational.Evidence) error {
	now := time.Now().UTC()

	// Link evidence
	evidenceLink := &risks.RiskEvidenceLink{
		RiskID:     riskID,
		EvidenceID: *evidence.ID,
		CreatedAt:  now,
	}
	if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(evidenceLink).Error; err != nil {
		return fmt.Errorf("failed to create evidence link: %w", err)
	}

	// Link subjects
	for _, subject := range evidence.Subjects {
		subjectLink := &risks.RiskSubjectLink{
			RiskID:    riskID,
			SubjectID: *subject.ID,
			CreatedAt: now,
		}
		if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(subjectLink).Error; err != nil {
			return fmt.Errorf("failed to create subject link: %w", err)
		}
	}

	// Link components
	for _, component := range evidence.Components {
		componentLink := &risks.RiskComponentLink{
			RiskID:      riskID,
			ComponentID: *component.ID,
			CreatedAt:   now,
		}
		if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(componentLink).Error; err != nil {
			return fmt.Errorf("failed to create component link: %w", err)
		}
	}

	// TODO: Link controls - derive from the RiskTemplate or from the evidence's subject → control
	// mapping once that relationship is established in the data model.

	return nil
}

// emitRiskEvent creates a risk event record
func (w *RiskEvidenceWorker) emitRiskEvent(ctx context.Context, riskID uuid.UUID, eventType string, payload map[string]interface{}) error {
	event := &risks.RiskEvent{
		RiskID:     riskID,
		EventType:  eventType,
		OccurredAt: time.Now().UTC(),
		Payload:    payload,
	}

	return w.db.WithContext(ctx).Create(event).Error
}
