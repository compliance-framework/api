package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
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

// resolvedSSPInfo groups a resolved SSP ID with the control links that matched.
type resolvedSSPInfo struct {
	SSPID        uuid.UUID
	ControlLinks []controlLinkInfo
}

// controlLinkInfo holds a catalog+control pair from a matching filter.
type controlLinkInfo struct {
	CatalogID uuid.UUID
	ControlID string
}

// RiskEvidenceWorker handles processing evidence and creating risks
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

// Work is the River work function for processing evidence and creating risks
func (w *RiskEvidenceWorker) Work(ctx context.Context, job *river.Job[RiskProcessEvidenceArgs]) error {
	args := job.Args

	w.logger.Infow("Processing risk evidence job",
		"evidence_id", args.EvidenceID,
		"evidence_end", args.EvidenceEnd,
		"status", args.Status,
	)

	// 1. Load evidence with relations
	evidence, err := w.loadEvidenceWithRelations(ctx, args.EvidenceID)
	if err != nil {
		w.logger.Errorw("Failed to load evidence", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	// 2. Resolution flow — always runs regardless of evidence status.
	// Removes stale evidence→risk links and transitions fully-resolved risks to "remediated".
	if err := w.handleEvidenceResolution(ctx, evidence); err != nil {
		w.logger.Errorw("Evidence resolution completed with errors", "error", err, "evidence_id", args.EvidenceID)
		// Continue to creation flow — resolution errors should not block risk creation.
	}

	// 3. Check evidence status early to avoid unnecessary work for satisfied evidence.
	statusData := evidence.Status.Data()
	if statusData.State != relational.EvidenceStatusNotSatisfied {
		w.logger.Infow("Evidence is not 'not-satisfied', skipping risk creation",
			"evidence_id", args.EvidenceID,
			"status", statusData.State,
		)
		return nil
	}

	// 4. Load risk templates based on _policy label before resolving SSPs.
	// If there are no matching templates, we can skip SSP resolution entirely.
	riskTemplates, err := w.loadRiskTemplates(ctx, evidence.Labels, args.EvidenceID)
	if err != nil {
		w.logger.Errorw("Failed to load risk templates", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	if len(riskTemplates) == 0 {
		w.logger.Infow("No matching risk templates found for evidence", "evidence_id", args.EvidenceID)
		return nil
	}

	// 5. Resolve SSPs via filter matching (replaces component-based resolution)
	sspInfos, err := w.resolveSSPsViaFilters(ctx, evidence.Labels)
	if err != nil {
		w.logger.Errorw("Failed to resolve SSPs via filters", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	if len(sspInfos) == 0 {
		w.logger.Infow("No SSPs resolved via filters for evidence", "evidence_id", args.EvidenceID)
		return nil
	}

	// 6. Filter risk templates by violation IDs
	filteredRiskTemplates, err := w.filterRiskTemplatesByViolations(riskTemplates, evidence.Props)
	if err != nil {
		w.logger.Errorw("Failed to filter risk templates by violations", "error", err, "evidence_id", args.EvidenceID)
		return err
	}

	// 7. Create/update risks for each template × SSP
	var errs []error
	for _, riskTemplate := range filteredRiskTemplates {
		if err := w.createOrUpdateRisksForSSPs(ctx, riskTemplate, evidence, sspInfos); err != nil {
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

	w.logger.Infow("Risk evidence job processed successfully",
		"evidence_id", args.EvidenceID,
		"risk_templates", len(filteredRiskTemplates),
		"ssps", len(sspInfos),
	)

	return nil
}

// resolveSSPsViaFilters resolves SSPs by evaluating evidence labels against all filters in-memory,
// then querying the DB for the filter→control→SSP path.
func (w *RiskEvidenceWorker) resolveSSPsViaFilters(ctx context.Context, evidenceLabels []relational.Labels) ([]resolvedSSPInfo, error) {
	// 1. Load only filters that have at least one control linked (via filter_controls).
	// Filters without controls can never resolve to an SSP, so loading them is wasteful.
	var filters []relational.Filter
	if err := w.db.WithContext(ctx).
		Where("id IN (SELECT DISTINCT filter_id FROM filter_controls)").
		Find(&filters).Error; err != nil {
		return nil, fmt.Errorf("failed to load filters: %w", err)
	}

	if len(filters) == 0 {
		return nil, nil
	}

	// 2. Normalize evidence labels into map[string][]string
	labelPairs := make([]struct{ Name, Value string }, len(evidenceLabels))
	for i, l := range evidenceLabels {
		labelPairs[i] = struct{ Name, Value string }{Name: l.Name, Value: l.Value}
	}
	normalizedLabels := labelfilter.NormalizeLabels(labelPairs)

	// 3. Evaluate each filter
	var matchingFilterIDs []uuid.UUID
	for _, f := range filters {
		filterData := f.Filter.Data()
		matches, err := labelfilter.MatchLabels(filterData.Scope, normalizedLabels)
		if err != nil {
			w.logger.Errorw("Invalid filter query operator",
				"error", err,
				"filter_id", f.ID,
			)
			continue
		}
		if matches {
			matchingFilterIDs = append(matchingFilterIDs, *f.ID)
		}
	}

	if len(matchingFilterIDs) == 0 {
		return nil, nil
	}

	w.logger.Debugw("Filters matched evidence labels",
		"matching_filter_count", len(matchingFilterIDs),
		"total_filters", len(filters),
	)

	// 4. Query filter_controls → SSPs via profile_controls to ensure catalog-scoped matching.
	// We join through profile_controls to guarantee that the catalog ID from the filter
	// matches the catalog the SSP's profile actually references. Without this, two controls
	// from different catalogs sharing the same control ID string (e.g. "AC-1") would
	// incorrectly cross-match.
	type filterControlRow struct {
		SystemSecurityPlanID uuid.UUID `gorm:"column:system_security_plan_id"`
		ControlCatalogID     uuid.UUID `gorm:"column:control_catalog_id"`
		ControlID            string    `gorm:"column:control_id"`
	}

	var rows []filterControlRow
	if err := w.db.WithContext(ctx).
		Table("filter_controls fc").
		Select("DISTINCT ssp.id AS system_security_plan_id, fc.control_catalog_id, fc.control_id").
		Joins("JOIN profile_controls pc ON CAST(pc.control_catalog_id AS uuid) = CAST(fc.control_catalog_id AS uuid) AND UPPER(pc.control_id) = UPPER(fc.control_id)").
		Joins("JOIN system_security_plans ssp ON CAST(ssp.profile_id AS uuid) = CAST(pc.profile_id AS uuid)").
		Joins("JOIN control_implementations ci ON CAST(ci.system_security_plan_id AS uuid) = CAST(ssp.id AS uuid)").
		Joins("JOIN implemented_requirements ir ON CAST(ir.control_implementation_id AS uuid) = CAST(ci.id AS uuid) AND UPPER(ir.control_id) = UPPER(fc.control_id)").
		Where("fc.filter_id IN ?", matchingFilterIDs).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to query SSPs via filter controls: %w", err)
	}

	if len(rows) == 0 {
		return nil, nil
	}

	// 5. Group by SSP ID
	sspMap := make(map[uuid.UUID]*resolvedSSPInfo)
	for _, row := range rows {
		info, exists := sspMap[row.SystemSecurityPlanID]
		if !exists {
			info = &resolvedSSPInfo{SSPID: row.SystemSecurityPlanID}
			sspMap[row.SystemSecurityPlanID] = info
		}
		info.ControlLinks = append(info.ControlLinks, controlLinkInfo{
			CatalogID: row.ControlCatalogID,
			ControlID: row.ControlID,
		})
	}

	result := make([]resolvedSSPInfo, 0, len(sspMap))
	for _, info := range sspMap {
		result = append(result, *info)
	}

	return result, nil
}

// RiskEvidenceWorker helper methods

// loadEvidenceWithRelations loads evidence with all required relations for risk processing
func (w *RiskEvidenceWorker) loadEvidenceWithRelations(ctx context.Context, evidenceID uuid.UUID) (*relational.Evidence, error) {
	var evidence relational.Evidence

	err := w.db.WithContext(ctx).
		Preload("Labels").
		Preload("Components").
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
		Preload("ThreatRefs", func(db *gorm.DB) *gorm.DB { return db.Order("system ASC, external_id ASC") }).
		Preload("LabelSchema", func(db *gorm.DB) *gorm.DB { return db.Order("key ASC") }).
		Preload("RemediationTemplate").
		Preload("RemediationTemplate.Tasks", func(db *gorm.DB) *gorm.DB { return db.Order("order_index ASC") }).
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

// filterRiskTemplatesByViolations filters risk templates based on violation IDs in evidence props
func (w *RiskEvidenceWorker) filterRiskTemplatesByViolations(riskTemplates []templates.RiskTemplate, evidenceProps datatypes.JSONSlice[relational.Prop]) ([]templates.RiskTemplate, error) {
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
func (w *RiskEvidenceWorker) extractViolationIDs(props datatypes.JSONSlice[relational.Prop]) []string {
	var violationIDs []string

	for _, prop := range props {
		propName := strings.ToLower(strings.TrimSpace(prop.Name))
		propValue := strings.TrimSpace(prop.Value)
		// Accept both current and legacy violation prop names.
		if (propName == "_violation_id" || propName == "violation_id") && propValue != "" {
			violationIDs = append(violationIDs, propValue)
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

// createOrUpdateRisksForSSPs creates or updates risks for each resolved SSP
func (w *RiskEvidenceWorker) createOrUpdateRisksForSSPs(ctx context.Context, riskTemplate templates.RiskTemplate, evidence *relational.Evidence, sspInfos []resolvedSSPInfo) error {
	var errs []error
	for _, sspInfo := range sspInfos {
		// Compute dedupe key: ssp_id + risk_template_id (+ optional label-based suffix)
		dedupeKey := w.computeDedupeKeyForSSP(riskTemplate, sspInfo.SSPID, evidence.Labels)

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
			err = w.updateExistingRisk(ctx, &existingRisk, evidence, sspInfo.ControlLinks)
		} else {
			// No existing risk - create new one
			err = w.createNewRiskForSSP(ctx, riskTemplate, evidence, sspInfo.SSPID, dedupeKey, sspInfo.ControlLinks)
		}

		if err != nil {
			w.logger.Errorw("Failed to create or update risk for SSP",
				"error", err,
				"evidence_id", evidence.UUID,
				"risk_template_id", riskTemplate.ID,
				"ssp_id", sspInfo.SSPID)
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// computeDedupeKeyForSSP computes the dedupe key for a risk.
// Base format: ssp_id:risk_template_id
// When the template declares DedupeLabelKeys, the corresponding evidence label values
// are appended as sorted key=value pairs, allowing the same template to produce
// distinct risks per unique combination (e.g. per-CVE).
func (w *RiskEvidenceWorker) computeDedupeKeyForSSP(riskTemplate templates.RiskTemplate, sspID uuid.UUID, evidenceLabels []relational.Labels) string {
	base := fmt.Sprintf("%s:%s", sspID.String(), riskTemplate.ID.String())

	if len(riskTemplate.DedupeLabelKeys) == 0 {
		return base
	}

	// Build a map of evidence labels for fast lookup
	labelMap := make(map[string]string, len(evidenceLabels))
	for _, l := range evidenceLabels {
		labelMap[l.Name] = l.Value
	}

	// Collect key=value pairs in sorted dedupe key order
	keys := make([]string, len(riskTemplate.DedupeLabelKeys))
	copy(keys, riskTemplate.DedupeLabelKeys)
	sort.Strings(keys)

	var parts []string
	for _, key := range keys {
		val := labelMap[key]
		parts = append(parts, fmt.Sprintf("%s=%s", key, val))
	}

	return base + ":" + strings.Join(parts, ",")
}

// updateExistingRisk updates an existing risk with new evidence.
// The save, link upserts, and event insertion run in a single transaction so that
// a partial failure cannot leave the risk with a bumped LastSeenAt but missing links/events.
func (w *RiskEvidenceWorker) updateExistingRisk(ctx context.Context, existingRisk *risks.Risk, evidence *relational.Evidence, controlLinks []controlLinkInfo) error {
	now := time.Now().UTC()

	// Capture previous value before mutation so the event payload is accurate.
	previousLastSeen := existingRisk.LastSeenAt

	// If the risk was remediated and new failing evidence arrives, re-open it.
	reopened := false
	oldStatus := existingRisk.Status
	if existingRisk.Status == string(risks.RiskStatusRemediated) {
		existingRisk.Status = string(risks.RiskStatusOpen)
		reopened = true
	}

	err := w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		existingRisk.LastSeenAt = now
		if err := tx.Save(existingRisk).Error; err != nil {
			return fmt.Errorf("failed to update existing risk: %w", err)
		}

		// Re-create all risk links (evidence, controls) for this new piece of evidence.
		// createRiskLinks is idempotent via OnConflict{DoNothing}, so this is safe for existing risks.
		if err := w.createRiskLinks(ctx, tx, *existingRisk.ID, existingRisk.SSPID, evidence, controlLinks); err != nil {
			return fmt.Errorf("failed to create risk links: %w", err)
		}

		if reopened {
			if err := w.emitRiskEvent(ctx, tx, *existingRisk.ID, string(risks.RiskEventTypeStatusChange), map[string]interface{}{
				"from":        oldStatus,
				"to":          string(risks.RiskStatusOpen),
				"evidence_id": evidence.UUID,
				"reason":      "new_failing_evidence",
			}); err != nil {
				return fmt.Errorf("failed to emit reopen status change event: %w", err)
			}
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
func (w *RiskEvidenceWorker) createNewRiskForSSP(ctx context.Context, riskTemplate templates.RiskTemplate, evidence *relational.Evidence, sspID uuid.UUID, dedupeKey string, controlLinks []controlLinkInfo) error {
	now := time.Now().UTC()

	// Resolve template fields if present, falling back to static values.
	title, statement, likelihoodHint, impactHint := w.resolveRiskTemplateFields(riskTemplate, evidence.Labels)

	newRisk := risks.Risk{
		Title:          title,
		Description:    statement,
		Status:         string(risks.RiskStatusOpen),
		SSPID:          sspID,
		RiskTemplateID: riskTemplate.ID,
		SourceType:     string(risks.RiskSourceTypeEvidenceAuto),
		DedupeKey:      dedupeKey,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}

	// Set likelihood and impact from resolved values if available
	if likelihoodHint != nil {
		newRisk.Likelihood = likelihoodHint
	}
	if impactHint != nil {
		newRisk.Impact = impactHint
	}

	err := w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&newRisk).Error; err != nil {
			return fmt.Errorf("failed to create new risk: %w", err)
		}
		if err := w.copyTemplateAssociationsToRisk(tx, *newRisk.ID, riskTemplate); err != nil {
			return fmt.Errorf("failed to copy risk template associations: %w", err)
		}
		if err := w.createRiskLinks(ctx, tx, *newRisk.ID, sspID, evidence, controlLinks); err != nil {
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

func (w *RiskEvidenceWorker) copyTemplateAssociationsToRisk(tx *gorm.DB, riskID uuid.UUID, riskTemplate templates.RiskTemplate) error {
	if len(riskTemplate.ThreatRefs) > 0 {
		rows := make([]risks.RiskThreatRef, 0, len(riskTemplate.ThreatRefs))
		for _, ref := range riskTemplate.ThreatRefs {
			rows = append(rows, risks.RiskThreatRef{
				RiskID:     riskID,
				System:     ref.System,
				ExternalID: ref.ExternalID,
				Title:      ref.Title,
				URL:        ref.URL,
			})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return err
		}
	}

	if riskTemplate.RemediationTemplate != nil && riskTemplate.RemediationTemplate.ID != nil {
		remediation := risks.RiskRemediationTemplate{
			RiskID:      riskID,
			Title:       riskTemplate.RemediationTemplate.Title,
			Description: riskTemplate.RemediationTemplate.Description,
		}
		if err := tx.Create(&remediation).Error; err != nil {
			return err
		}

		if len(riskTemplate.RemediationTemplate.Tasks) > 0 {
			tasks := make([]risks.RiskRemediationTask, 0, len(riskTemplate.RemediationTemplate.Tasks))
			for _, task := range riskTemplate.RemediationTemplate.Tasks {
				tasks = append(tasks, risks.RiskRemediationTask{
					RiskRemediationTemplateID: *remediation.ID,
					Title:                     task.Title,
					OrderIndex:                task.OrderIndex,
				})
			}
			if err := tx.Create(&tasks).Error; err != nil {
				return err
			}
		}
	}

	return nil
}

// createRiskLinks creates the currently supported links for a risk (evidence, controls, and components).
// Accepts a *gorm.DB so the caller can pass a transaction.
// Uses OnConflict{DoNothing} throughout so retries are idempotent.
func (w *RiskEvidenceWorker) createRiskLinks(ctx context.Context, db *gorm.DB, riskID uuid.UUID, riskSSPID uuid.UUID, evidence *relational.Evidence, controlLinks []controlLinkInfo) error {
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

	// Link controls
	for _, cl := range controlLinks {
		link := &risks.RiskControlLink{
			RiskID:    riskID,
			CatalogID: cl.CatalogID,
			ControlID: cl.ControlID,
			CreatedAt: now,
		}
		if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(link).Error; err != nil {
			return fmt.Errorf("failed to create control link: %w", err)
		}
	}

	// Link components — if the evidence has system components belonging to the same SSP, bind them.
	if len(evidence.Components) > 0 {
		// Prefetch SystemImplementations to map component → SSP, avoiding N+1.
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

		for _, component := range evidence.Components {
			componentSSPID, ok := systemImplToSSPID[component.SystemImplementationId]
			if !ok {
				continue
			}
			// Only link components belonging to the same SSP as the risk.
			if componentSSPID != riskSSPID {
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
	}

	return nil
}

// handleEvidenceResolution evaluates all active risks linked to this evidence stream and
// removes links that are no longer justified (evidence satisfied or violations no longer match).
// When a risk loses its last evidence link it is transitioned to "remediated" (or an audit
// event is emitted if the risk is in "risk-accepted" status).
func (w *RiskEvidenceWorker) handleEvidenceResolution(ctx context.Context, evidence *relational.Evidence) error {
	if evidence.UUID == uuid.Nil {
		return nil
	}

	statusData := evidence.Status.Data()
	evidenceSatisfied := statusData.State == relational.EvidenceStatusSatisfied
	evidenceViolationIDs := w.extractViolationIDs(evidence.Props)

	// Load all evidence links for this stream.
	var links []risks.RiskEvidenceLink
	if err := w.db.WithContext(ctx).
		Where("evidence_id = ?", evidence.UUID).
		Find(&links).Error; err != nil {
		return fmt.Errorf("failed to load evidence links: %w", err)
	}

	if len(links) == 0 {
		return nil
	}

	// Collect unique risk IDs from the links.
	riskIDs := make([]uuid.UUID, 0, len(links))
	for _, link := range links {
		riskIDs = append(riskIDs, link.RiskID)
	}

	// Batch-load the linked risks.
	var linkedRisks []risks.Risk
	if err := w.db.WithContext(ctx).
		Where("id IN ?", riskIDs).
		Find(&linkedRisks).Error; err != nil {
		return fmt.Errorf("failed to load linked risks: %w", err)
	}

	riskByID := make(map[uuid.UUID]*risks.Risk, len(linkedRisks))
	for i := range linkedRisks {
		riskByID[*linkedRisks[i].ID] = &linkedRisks[i]
	}

	// Collect unique template IDs to batch-load.
	templateIDs := make(map[uuid.UUID]struct{})
	for i := range linkedRisks {
		if linkedRisks[i].RiskTemplateID != nil {
			templateIDs[*linkedRisks[i].RiskTemplateID] = struct{}{}
		}
	}

	// Batch-load risk templates.
	templateByID := make(map[uuid.UUID]*templates.RiskTemplate)
	if len(templateIDs) > 0 {
		templateIDList := make([]uuid.UUID, 0, len(templateIDs))
		for id := range templateIDs {
			templateIDList = append(templateIDList, id)
		}

		var riskTemplates []templates.RiskTemplate
		if err := w.db.WithContext(ctx).
			Select("id", "violation_ids").
			Where("id IN ?", templateIDList).
			Find(&riskTemplates).Error; err != nil {
			return fmt.Errorf("failed to batch-load risk templates: %w", err)
		}

		for i := range riskTemplates {
			templateByID[*riskTemplates[i].ID] = &riskTemplates[i]
		}
	}

	var errs []error
	for _, link := range links {
		risk, ok := riskByID[link.RiskID]
		if !ok {
			continue
		}
		// Skip risks that are already closed or remediated — nothing to resolve.
		if risk.Status == string(risks.RiskStatusClosed) || risk.Status == string(risks.RiskStatusRemediated) {
			continue
		}

		remove := w.shouldRemoveEvidenceLink(risk, evidenceSatisfied, evidenceViolationIDs, templateByID)
		if !remove {
			continue
		}

		if err := w.resolveRiskEvidenceLink(ctx, risk, evidence.UUID); err != nil {
			w.logger.Errorw("Failed to resolve risk evidence link",
				"error", err, "risk_id", risk.ID, "evidence_id", evidence.UUID)
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// shouldRemoveEvidenceLink decides whether a risk's evidence link should be removed.
func (w *RiskEvidenceWorker) shouldRemoveEvidenceLink(risk *risks.Risk, evidenceSatisfied bool, evidenceViolationIDs []string, templateByID map[uuid.UUID]*templates.RiskTemplate) bool {
	// Satisfied evidence means the underlying condition is fixed — always remove.
	if evidenceSatisfied {
		return true
	}

	// Evidence is still not-satisfied. Check whether the risk template's violation IDs
	// still intersect with the evidence's current violations.
	if risk.RiskTemplateID == nil {
		return false
	}

	tmpl, ok := templateByID[*risk.RiskTemplateID]
	if !ok {
		// If the template is gone we can't determine relevance — keep the link.
		return false
	}

	// Template with empty ViolationIDs matches any not-satisfied evidence — keep link.
	if len(tmpl.ViolationIDs) == 0 {
		return false
	}

	// If none of the template's violations appear in the current evidence → remove.
	return !w.violationMatches(tmpl.ViolationIDs, evidenceViolationIDs)
}

// resolveRiskEvidenceLink removes a single evidence link from a risk and, if no links remain,
// transitions the risk to "remediated" (or emits an audit event for "risk-accepted" risks).
func (w *RiskEvidenceWorker) resolveRiskEvidenceLink(ctx context.Context, risk *risks.Risk, evidenceStreamID uuid.UUID) error {
	return w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete the evidence link.
		result := tx.Delete(&risks.RiskEvidenceLink{}, "risk_id = ? AND evidence_id = ?", *risk.ID, evidenceStreamID)
		if result.Error != nil {
			return fmt.Errorf("failed to delete evidence link: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return nil // already removed
		}

		// Emit evidence_unlinked event.
		if err := w.emitRiskEvent(ctx, tx, *risk.ID, string(risks.RiskEventTypeEvidenceUnlink), map[string]interface{}{
			"evidence_id": evidenceStreamID.String(),
			"reason":      "auto_resolution",
		}); err != nil {
			return fmt.Errorf("failed to emit evidence unlink event: %w", err)
		}

		// Count remaining evidence links for this risk.
		var remaining int64
		if err := tx.Model(&risks.RiskEvidenceLink{}).
			Where("risk_id = ?", *risk.ID).
			Count(&remaining).Error; err != nil {
			return fmt.Errorf("failed to count remaining evidence links: %w", err)
		}

		if remaining > 0 {
			w.logger.Infow("Evidence link removed but risk still has remaining links",
				"risk_id", risk.ID, "evidence_id", evidenceStreamID, "remaining", remaining)
			return nil
		}

		// No evidence links remain — decide based on risk status.
		if risk.Status == string(risks.RiskStatusRiskAccepted) {
			// Do NOT auto-close; emit audit event only.
			if err := w.emitRiskEvent(ctx, tx, *risk.ID, string(risks.RiskEventTypeEvidenceRecovered), map[string]interface{}{
				"evidence_id": evidenceStreamID.String(),
			}); err != nil {
				return fmt.Errorf("failed to emit evidence_recovered event: %w", err)
			}
			w.logger.Infow("Risk is risk-accepted; emitted evidence_recovered event without status change",
				"risk_id", risk.ID, "evidence_id", evidenceStreamID)
			return nil
		}

		// Transition to remediated.
		oldStatus := risk.Status
		if err := tx.Model(risk).Update("status", string(risks.RiskStatusRemediated)).Error; err != nil {
			return fmt.Errorf("failed to transition risk to remediated: %w", err)
		}
		if err := w.emitRiskEvent(ctx, tx, *risk.ID, string(risks.RiskEventTypeStatusChange), map[string]interface{}{
			"from":   oldStatus,
			"to":     string(risks.RiskStatusRemediated),
			"reason": "all_evidence_resolved",
		}); err != nil {
			return fmt.Errorf("failed to emit status change event: %w", err)
		}

		w.logger.Infow("Risk transitioned to remediated",
			"risk_id", risk.ID, "evidence_id", evidenceStreamID, "from_status", oldStatus)
		return nil
	})
}

// resolveRiskTemplateFields renders the template fields (title, statement, likelihood, impact)
// using evidence labels. If a template string is set it is rendered; otherwise the static value
// is returned. Rendering errors are logged but non-fatal — the static fallback is used instead.
func (w *RiskEvidenceWorker) resolveRiskTemplateFields(rt templates.RiskTemplate, evidenceLabels []relational.Labels) (title string, statement string, likelihoodHint *string, impactHint *string) {
	title = rt.Title
	statement = rt.Statement
	likelihoodHint = normalizeRenderedRiskLevel(rt.LikelihoodHint)
	impactHint = normalizeRenderedRiskLevel(rt.ImpactHint)

	// If no template fields are set, return static values.
	if rt.TitleTemplate == nil && rt.StatementTemplate == nil && rt.LikelihoodHintTemplate == nil && rt.ImpactHintTemplate == nil {
		return
	}

	// Build label map from evidence labels.
	labelMap := make(map[string]string, len(evidenceLabels))
	for _, l := range evidenceLabels {
		labelMap[l.Name] = l.Value
	}

	if rt.TitleTemplate != nil {
		rendered, err := templates.RenderTemplatePublic(*rt.TitleTemplate, labelMap)
		if err != nil {
			w.logger.Warnw("Failed to render title template, using static title",
				"error", err, "risk_template_id", rt.ID)
		} else if rendered != "" {
			title = rendered
		}
	}

	if rt.StatementTemplate != nil {
		rendered, err := templates.RenderTemplatePublic(*rt.StatementTemplate, labelMap)
		if err != nil {
			w.logger.Warnw("Failed to render statement template, using static statement",
				"error", err, "risk_template_id", rt.ID)
		} else if rendered != "" {
			statement = rendered
		}
	}

	if rt.LikelihoodHintTemplate != nil {
		rendered, err := templates.RenderTemplatePublic(*rt.LikelihoodHintTemplate, labelMap)
		if err != nil {
			w.logger.Warnw("Failed to render likelihood hint template, using static hint",
				"error", err, "risk_template_id", rt.ID)
		} else if rendered != "" {
			normalized := normalizeRenderedRiskLevel(&rendered)
			if normalized == nil {
				w.logger.Warnw("Rendered likelihood hint template produced invalid risk level, using static hint",
					"risk_template_id", rt.ID, "rendered_value", rendered)
			} else {
				likelihoodHint = normalized
			}
		}
	}

	if rt.ImpactHintTemplate != nil {
		rendered, err := templates.RenderTemplatePublic(*rt.ImpactHintTemplate, labelMap)
		if err != nil {
			w.logger.Warnw("Failed to render impact hint template, using static hint",
				"error", err, "risk_template_id", rt.ID)
		} else if rendered != "" {
			normalized := normalizeRenderedRiskLevel(&rendered)
			if normalized == nil {
				w.logger.Warnw("Rendered impact hint template produced invalid risk level, using static hint",
					"risk_template_id", rt.ID, "rendered_value", rendered)
			} else {
				impactHint = normalized
			}
		}
	}

	return
}

func normalizeRenderedRiskLevel(level *string) *string {
	if level == nil {
		return nil
	}

	normalized := risks.NormalizeRiskLevel(*level)
	if normalized == "" || !normalized.IsValid() {
		return nil
	}

	value := string(normalized)
	return &value
}

// emitRiskEvent creates a risk event record using the provided DB handle.
// Accepts a *gorm.DB so the caller can pass a transaction handle.
func (w *RiskEvidenceWorker) emitRiskEvent(ctx context.Context, db *gorm.DB, riskID uuid.UUID, eventType string, payload map[string]interface{}) error {
	occurredAt := time.Now().UTC()
	payloadMap := datatypes.JSONMap(payload)
	details := risks.BuildRiskEventDetails(eventType, payloadMap, occurredAt)

	event := &risks.RiskEvent{
		RiskID:     riskID,
		EventType:  eventType,
		OccurredAt: occurredAt,
		Details:    &details,
		Payload:    payloadMap,
	}

	return db.WithContext(ctx).Create(event).Error
}
