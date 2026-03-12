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
	"gorm.io/datatypes"
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

	// 2. Risk Templates: Load RiskTemplates based on `_policy` label from evidence
	riskTemplates, err := w.loadRiskTemplates(ctx, evidence.Labels, args.EvidenceID)
	if err != nil {
		w.logger.Errorw("Failed to load risk templates", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	if len(riskTemplates) == 0 {
		w.logger.Infow("No matching risk templates found for evidence", "evidence_id", args.EvidenceID)
		return nil
	}

	// 3. Violation Filtering: Filter the risk templates by checking the fired violation.id against risk_template.violation_ids
	filteredRiskTemplates, err := w.filterRiskTemplatesByViolations(riskTemplates, evidence.Labels)
	if err != nil {
		w.logger.Errorw("Failed to filter risk templates by violations", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	// 4. Risk Creation/Update: For each candidate RiskTemplate, create one risk per SSP.
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
		return nil, fmt.Errorf("failed to load evidence %v: %w", evidenceID, err)
	}

	return &evidence, nil
}

// loadRiskTemplates loads risk templates based on the _policy label from evidence
// matching against the policy_package field in risk_template.
// Supports multiple _policy labels. Label names and values are matched case-insensitively,
// and label values are trimmed of whitespace.
func (w *RiskEvidenceWorker) loadRiskTemplates(ctx context.Context, evidenceLabels []relational.Labels, evidenceID uuid.UUID) ([]templates.RiskTemplate, error) {
	// Extract all _policy label values from evidence (case-insensitive, trimmed, deduplicated)
	policyPackages := make(map[string]struct{})
	for _, label := range evidenceLabels {
		if strings.EqualFold(label.Name, "_policy") {
			normalized := strings.ToLower(strings.TrimSpace(label.Value))
			if normalized != "" {
				policyPackages[normalized] = struct{}{}
			}
		}
	}

	if len(policyPackages) == 0 {
		w.logger.Debugw("No _policy label found in evidence", "evidence_id", evidenceID)
		return nil, nil
	}

	// Convert map keys to slice for IN query
	policyPackageList := make([]string, 0, len(policyPackages))
	for pkg := range policyPackages {
		policyPackageList = append(policyPackageList, pkg)
	}
	// Ensure deterministic order for queries, logs, and error messages
	sort.Strings(policyPackageList)

	// Query risk templates where policy_package matches any of the _policy label values (case-insensitive)
	// Note: We normalize evidence labels to lowercase, so we expect policy_package to be stored in lowercase
	var riskTemplates []templates.RiskTemplate
	err := w.db.WithContext(ctx).
		Where("policy_package IN ? AND is_active = ?", policyPackageList, true).
		Find(&riskTemplates).Error

	if err != nil {
		return nil, fmt.Errorf("failed to load risk templates for policy packages %v: %w", policyPackageList, err)
	}

	w.logger.Debugw("Loaded risk templates by policy package",
		"evidence_id", evidenceID,
		"policy_packages", policyPackageList,
		"count", len(riskTemplates))

	return riskTemplates, nil
}

// filterRiskTemplatesByViolations filters risk templates based on violation IDs in evidence labels
func (w *RiskEvidenceWorker) filterRiskTemplatesByViolations(riskTemplates []templates.RiskTemplate, evidenceLabels []relational.Labels) ([]templates.RiskTemplate, error) {
	// Extract violation IDs from evidence labels
	violationIDs := w.extractViolationIDs(evidenceLabels)

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

// extractViolationIDs extracts violation IDs from evidence labels
func (w *RiskEvidenceWorker) extractViolationIDs(labels []relational.Labels) []string {
	var violationIDs []string

	for _, label := range labels {
		labelName := strings.ToLower(strings.TrimSpace(label.Name))
		labelValue := strings.TrimSpace(label.Value)
		// Accept both current and legacy violation label names.
		if (labelName == "_violation_id" || labelName == "violation_id") && labelValue != "" {
			violationIDs = append(violationIDs, labelValue)
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

	// Get unique SSP IDs from evidence components
	sspIDs, err := w.extractSSPIDsFromComponents(ctx, evidence.Components)
	if err != nil {
		return fmt.Errorf("failed to extract SSP IDs from components: %w", err)
	}
	// Create/update one risk per SSP
	// If no SSPIDs are valid, no risks are needed
	var errs []error
	for _, sspID := range sspIDs {
		// Compute dedupe key: ssp_id + risk_template_id
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
				"evidence_id", evidence.UUID,
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
// Format: ssp_id:risk_template_id
func (w *RiskEvidenceWorker) computeDedupeKeyForSSP(riskTemplate templates.RiskTemplate, evidence *relational.Evidence, sspID uuid.UUID) string {
	return fmt.Sprintf("%s:%s", sspID.String(), riskTemplate.ID.String())
}

// updateExistingRisk updates an existing risk with new evidence.
// The save, link upserts, and event insertion run in a single transaction so that
// a partial failure cannot leave the risk with a bumped LastSeenAt but missing links/events.
func (w *RiskEvidenceWorker) updateExistingRisk(ctx context.Context, existingRisk *risks.Risk, riskTemplate templates.RiskTemplate, evidence *relational.Evidence) error {
	now := time.Now().UTC()

	// Capture previous value before mutation so the event payload is accurate.
	previousLastSeen := existingRisk.LastSeenAt

	err := w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		existingRisk.LastSeenAt = now
		if err := tx.Save(existingRisk).Error; err != nil {
			return fmt.Errorf("failed to update existing risk: %w", err)
		}

		// Re-create all risk links (evidence, subjects, components) for this new piece of evidence.
		// createRiskLinks is idempotent via OnConflict{DoNothing}, so this is safe for existing risks
		// and also keeps subject/component associations up to date as new evidence arrives.
		if err := w.createRiskLinks(ctx, tx, *existingRisk.ID, existingRisk.SSPID, evidence); err != nil {
			return fmt.Errorf("failed to create risk links: %w", err)
		}

		// Emit a risk_event(last_seen) using the typed constant.
		if err := w.emitRiskEvent(ctx, tx, *existingRisk.ID, string(risks.RiskEventTypeLastSeen), map[string]interface{}{
			"evidence_id":        evidence.UUID,
			"previous_last_seen": previousLastSeen,
			"new_last_seen":      now,
		}); err != nil {
			return fmt.Errorf("failed to emit risk event: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	w.logger.Infow("Updated existing risk",
		"risk_id", existingRisk.ID,
		"evidence_id", evidence.UUID,
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
		if err := w.createRiskLinks(ctx, tx, *newRisk.ID, sspID, evidence); err != nil {
			return err
		}
		// Emit a risk_event(created) using the typed constant
		if err := w.emitRiskEvent(ctx, tx, *newRisk.ID, string(risks.RiskEventTypeCreated), map[string]interface{}{
			"evidence_id": evidence.UUID,
			"template_id": riskTemplate.ID,
			"dedupe_key":  dedupeKey,
			"ssp_id":      sspID,
		}); err != nil {
			return fmt.Errorf("failed to emit created risk event: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	w.logger.Infow("Created new risk",
		"risk_id", newRisk.ID,
		"evidence_id", evidence.UUID,
		"risk_template_id", riskTemplate.ID,
		"ssp_id", sspID,
		"dedupe_key", dedupeKey,
	)

	return nil
}

// createRiskLinks creates all necessary links for a risk (evidence, subject, component, control).
// Accepts a *gorm.DB so the caller can pass a transaction.
// Uses OnConflict{DoNothing} throughout so retries are idempotent.
func (w *RiskEvidenceWorker) createRiskLinks(ctx context.Context, db *gorm.DB, riskID uuid.UUID, riskSSPID uuid.UUID, evidence *relational.Evidence) error {
	now := time.Now().UTC()
	if evidence.UUID == uuid.Nil {
		evidenceID := uuid.Nil
		if evidence.ID != nil {
			evidenceID = *evidence.ID
		}
		return fmt.Errorf("evidence %s is missing stream uuid", evidenceID)
	}

	// Link evidence
	evidenceLink := &risks.RiskEvidenceLink{
		RiskID:     riskID,
		EvidenceID: evidence.UUID,
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

	// Prefetch SystemImplementations for all evidence components to avoid an N+1 query pattern.
	systemImplIDs := make([]uuid.UUID, 0, len(evidence.Components))
	seenSystemImplIDs := make(map[uuid.UUID]struct{}, len(evidence.Components))
	for _, component := range evidence.Components {
		systemImplID := component.SystemImplementationId
		if systemImplID == uuid.Nil {
			continue
		}
		if _, seen := seenSystemImplIDs[systemImplID]; seen {
			continue
		}
		seenSystemImplIDs[systemImplID] = struct{}{}
		systemImplIDs = append(systemImplIDs, systemImplID)
	}

	systemImplToSSPID := make(map[uuid.UUID]uuid.UUID, len(systemImplIDs))
	if len(systemImplIDs) > 0 {
		var systemImpls []relational.SystemImplementation
		if err := db.WithContext(ctx).
			Select("id", "system_security_plan_id").
			Where("id IN ?", systemImplIDs).
			Find(&systemImpls).Error; err != nil {
			return fmt.Errorf("failed to prefetch components' system implementations: %w", err)
		}
		for _, systemImpl := range systemImpls {
			if systemImpl.ID == nil {
				continue
			}
			systemImplToSSPID[*systemImpl.ID] = systemImpl.SystemSecurityPlanId
		}
	}

	// Link components
	for _, component := range evidence.Components {
		componentSSPID, ok := systemImplToSSPID[component.SystemImplementationId]
		if !ok {
			w.logger.Warnw("Component's SystemImplementation not found, skipping component link",
				"component_id", component.ID,
				"system_implementation_id", component.SystemImplementationId,
				"risk_id", riskID)
			continue
		}

		// Skip if component belongs to a different SSP
		if componentSSPID != riskSSPID {
			w.logger.Warnw("Component belongs to different SSP than risk, skipping component link",
				"component_id", component.ID,
				"component_ssp_id", componentSSPID,
				"risk_ssp_id", riskSSPID,
				"risk_id", riskID)
			continue
		}

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

// emitRiskEvent creates a risk event record using the provided DB handle.
// Accepts a *gorm.DB so the caller can pass a transaction handle.
func (w *RiskEvidenceWorker) emitRiskEvent(ctx context.Context, db *gorm.DB, riskID uuid.UUID, eventType string, payload map[string]interface{}) error {
	event := &risks.RiskEvent{
		RiskID:     riskID,
		EventType:  eventType,
		OccurredAt: time.Now().UTC(),
		Payload:    datatypes.JSONMap(payload),
	}

	return db.WithContext(ctx).Create(event).Error
}
