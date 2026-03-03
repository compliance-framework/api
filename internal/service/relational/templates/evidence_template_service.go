package templates

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	maxEvidenceTemplateFieldLength    = maxRiskTemplateFieldLength
	maxEvidenceTemplateSelectorLabels = 50
	maxEvidenceTemplateLabelSchema    = 100
	maxEvidenceTemplateRiskLinks      = 200
	maxEvidenceTemplateSubjectLinks   = 200

	evidenceTemplateMethodTest      = "TEST"
	evidenceTemplateMethodExamine   = "EXAMINE"
	evidenceTemplateMethodInterview = "INTERVIEW"
)

var allowedEvidenceTemplateMethods = map[string]struct{}{
	evidenceTemplateMethodTest:      {},
	evidenceTemplateMethodExamine:   {},
	evidenceTemplateMethodInterview: {},
}

func normalizeEvidenceTemplateMethod(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func isValidEvidenceTemplateMethod(value string) bool {
	_, ok := allowedEvidenceTemplateMethods[normalizeEvidenceTemplateMethod(value)]
	return ok
}

// EvidenceTemplateService manages evidence templates.
type EvidenceTemplateService struct {
	db *gorm.DB
}

func NewEvidenceTemplateService(db *gorm.DB) *EvidenceTemplateService {
	return &EvidenceTemplateService{db: db}
}

type EvidenceTemplateListFilters struct {
	PluginID      *string
	PolicyPackage *string
	IsActive      *bool
}

type EvidenceTemplateListParams struct {
	Filters EvidenceTemplateListFilters
	Limit   int
	Offset  int
}

type EvidenceTemplateSelectorLabelInput struct {
	Key   string
	Value string
}

type EvidenceTemplateLabelSchemaFieldInput struct {
	Key         string
	Description *string
	Required    bool
}

type EvidenceTemplatePayload struct {
	PluginID           string
	PolicyPackage      string
	Title              string
	Description        string
	Methods            []string
	IsActive           *bool
	SelectorLabels     []EvidenceTemplateSelectorLabelInput
	LabelSchema        []EvidenceTemplateLabelSchemaFieldInput
	RiskTemplateIDs    []uuid.UUID
	SubjectTemplateIDs []uuid.UUID
}

func (s *EvidenceTemplateService) List(params EvidenceTemplateListParams) ([]EvidenceTemplate, int64, error) {
	query := s.db.Model(&EvidenceTemplate{})

	if params.Filters.PluginID != nil {
		pluginID := strings.TrimSpace(*params.Filters.PluginID)
		if pluginID != "" {
			query = query.Where("plugin_id = ?", pluginID)
		}
	}
	if params.Filters.PolicyPackage != nil {
		policyPackage := strings.TrimSpace(*params.Filters.PolicyPackage)
		if policyPackage != "" {
			query = query.Where("policy_package = ?", policyPackage)
		}
	}
	if params.Filters.IsActive != nil {
		query = query.Where("is_active = ?", *params.Filters.IsActive)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []EvidenceTemplate
	if err := query.
		Preload("SelectorLabels", preloadEvidenceTemplateSelectorLabels).
		Preload("LabelSchema", preloadEvidenceTemplateLabelSchema).
		Preload("RiskTemplates").
		Preload("SubjectTemplates").
		Order("created_at desc").
		Limit(params.Limit).
		Offset(params.Offset).
		Find(&rows).Error; err != nil {
		return nil, 0, err
	}

	return rows, total, nil
}

func (s *EvidenceTemplateService) GetByID(id uuid.UUID) (*EvidenceTemplate, error) {
	return fetchEvidenceTemplateByID(s.db, id)
}

func (s *EvidenceTemplateService) Create(payload EvidenceTemplatePayload) (*EvidenceTemplate, error) {
	if err := validateEvidenceTemplatePayload(&payload); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	if err := validateEvidenceTemplateLinkedIDs(tx, payload.RiskTemplateIDs, payload.SubjectTemplateIDs); err != nil {
		tx.Rollback()
		return nil, err
	}

	row := EvidenceTemplate{
		PluginID:      payload.PluginID,
		PolicyPackage: payload.PolicyPackage,
		Title:         payload.Title,
		Description:   payload.Description,
		Methods:       datatypes.NewJSONSlice(payload.Methods),
		IsActive:      true,
	}
	if payload.IsActive != nil {
		row.IsActive = *payload.IsActive
	}

	if err := tx.Select(
		"ID",
		"CreatedAt",
		"UpdatedAt",
		"PluginID",
		"PolicyPackage",
		"Title",
		"Description",
		"Methods",
		"IsActive",
	).Create(&row).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if payload.IsActive != nil && !*payload.IsActive {
		// GORM applies the model default (`default:true`) for false booleans in this insert path
		// under Postgres. Force the persisted value so create behavior matches the API payload.
		if err := tx.Model(&EvidenceTemplate{}).Where("id = ?", *row.ID).Update("is_active", false).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	if err := replaceEvidenceTemplateSelectorLabels(tx, *row.ID, payload.SelectorLabels); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceEvidenceTemplateLabelSchema(tx, *row.ID, payload.LabelSchema); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceEvidenceTemplateRiskLinks(tx, *row.ID, payload.RiskTemplateIDs); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceEvidenceTemplateSubjectLinks(tx, *row.ID, payload.SubjectTemplateIDs); err != nil {
		tx.Rollback()
		return nil, err
	}

	created, err := fetchEvidenceTemplateByID(tx, *row.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return created, nil
}

func (s *EvidenceTemplateService) Update(id uuid.UUID, payload EvidenceTemplatePayload) (*EvidenceTemplate, error) {
	if err := validateEvidenceTemplatePayload(&payload); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	var existing EvidenceTemplate
	if err := tx.First(&existing, "id = ?", id).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := validateEvidenceTemplateLinkedIDs(tx, payload.RiskTemplateIDs, payload.SubjectTemplateIDs); err != nil {
		tx.Rollback()
		return nil, err
	}

	existing.PluginID = payload.PluginID
	existing.PolicyPackage = payload.PolicyPackage
	existing.Title = payload.Title
	existing.Description = payload.Description
	existing.Methods = datatypes.NewJSONSlice(payload.Methods)
	if payload.IsActive != nil {
		existing.IsActive = *payload.IsActive
	}

	if err := tx.Omit("SelectorLabels", "LabelSchema", "RiskTemplates", "SubjectTemplates").Save(&existing).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := replaceEvidenceTemplateSelectorLabels(tx, *existing.ID, payload.SelectorLabels); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceEvidenceTemplateLabelSchema(tx, *existing.ID, payload.LabelSchema); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceEvidenceTemplateRiskLinks(tx, *existing.ID, payload.RiskTemplateIDs); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceEvidenceTemplateSubjectLinks(tx, *existing.ID, payload.SubjectTemplateIDs); err != nil {
		tx.Rollback()
		return nil, err
	}

	updated, err := fetchEvidenceTemplateByID(tx, *existing.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return updated, nil
}

func (s *EvidenceTemplateService) Delete(id uuid.UUID) error {
	tx := s.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer rollbackTxOnPanic(tx)

	var existing EvidenceTemplate
	if err := tx.Select("id").First(&existing, "id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Delete(&EvidenceTemplateSelectorLabel{}, "evidence_template_id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&EvidenceTemplateLabelSchemaField{}, "evidence_template_id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&EvidenceTemplateRiskTemplate{}, "evidence_template_id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&EvidenceTemplateSubjectTemplate{}, "evidence_template_id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&EvidenceTemplate{}, "id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// FindMatchesForEvidence returns evidence templates whose selector labels all match the given label map.
// Keys in labelsByKey are normalized to lowercase inside this function, consistent with the
// labelfilter SQL path (lower(el.labels_name)) and selector key normalization at write time.
func (s *EvidenceTemplateService) FindMatchesForEvidence(labelsByKey map[string]string) ([]EvidenceTemplate, error) {
	// Normalize incoming label keys to lowercase, mirroring the SQL lower() semantics so
	// callers do not need to pre-lowercase keys.
	normalizedLabels := make(map[string]string, len(labelsByKey))
	for k, v := range labelsByKey {
		normalizedLabels[strings.ToLower(k)] = v
	}

	// Phase 1: load only selector labels to keep the candidate scan lightweight.
	// Preloading LabelSchema, RiskTemplates, and SubjectTemplates for every active
	// template would waste I/O for templates that won't match.
	var candidates []EvidenceTemplate
	if err := s.db.
		Where("is_active = ?", true).
		Preload("SelectorLabels", preloadEvidenceTemplateSelectorLabels).
		Order("created_at asc").
		Find(&candidates).Error; err != nil {
		return nil, err
	}

	matchedIDs := make([]uuid.UUID, 0, len(candidates))
	for _, tmpl := range candidates {
		if evaluateFilterInMemory(SelectorLabelsToFilter(tmpl.SelectorLabels), normalizedLabels) {
			matchedIDs = append(matchedIDs, *tmpl.ID)
		}
	}

	if len(matchedIDs) == 0 {
		return []EvidenceTemplate{}, nil
	}

	// Phase 2: load full associations only for the matched templates.
	var matched []EvidenceTemplate
	if err := s.db.
		Where("id IN ?", matchedIDs).
		Preload("SelectorLabels", preloadEvidenceTemplateSelectorLabels).
		Preload("LabelSchema", preloadEvidenceTemplateLabelSchema).
		Preload("RiskTemplates").
		Preload("SubjectTemplates").
		Order("created_at asc").
		Find(&matched).Error; err != nil {
		return nil, err
	}

	return matched, nil
}

// evaluateFilterInMemory evaluates a labelfilter.Filter against an in-memory label map,
// mirroring the SQL semantics of GetEvidenceSearchByFilterQuery (case-insensitive via EqualFold).
// A Filter with a nil Scope (e.g. returned by SelectorLabelsToFilter for empty selectors) returns false.
func evaluateFilterInMemory(filter labelfilter.Filter, labelsByKey map[string]string) bool {
	if filter.Scope == nil {
		return false
	}
	return evaluateScopeInMemory(*filter.Scope, labelsByKey)
}

func evaluateScopeInMemory(scope labelfilter.Scope, labelsByKey map[string]string) bool {
	if scope.IsQuery() {
		return evaluateQueryInMemory(*scope.Query, labelsByKey)
	}
	if scope.IsCondition() {
		return evaluateConditionInMemory(*scope.Condition, labelsByKey)
	}
	// todo[sonnet]: this code might be dead code. Left as part of the implementation design.
	// review if needed in the future and consider removing it.
	// A Scope with both Query and Condition nil is never produced by SelectorLabelsToFilter.
	return false
}

func evaluateQueryInMemory(query labelfilter.Query, labelsByKey map[string]string) bool {
	switch strings.ToLower(query.Operator) {
	case "and":
		if len(query.Scopes) == 0 {
			return false // no selectors = no match (consistent with SelectorLabelsToFilter nil-Scope path)
		}
		for _, scope := range query.Scopes {
			if !evaluateScopeInMemory(scope, labelsByKey) {
				return false
			}
		}
		return true
	case "or":
		// todo[sonnet]: this code might be dead code. Left as part of the implementation design.
		// review if needed in the future and consider removing it.
		// SelectorLabelsToFilter only ever emits "AND" queries; the OR path is never reached by
		// the current sole caller (FindMatchesForEvidence).
		for _, scope := range query.Scopes {
			if evaluateScopeInMemory(scope, labelsByKey) {
				return true
			}
		}
		return false
	}
	return false
}

func evaluateConditionInMemory(condition labelfilter.Condition, labelsByKey map[string]string) bool {
	value, ok := labelsByKey[strings.ToLower(condition.Label)]
	if !ok {
		// todo[sonnet]: this code might be dead code. Left as part of the implementation design.
		// review if needed in the future and consider removing it.
		// SelectorLabelsToFilter only emits "=" operators; the "!=" absent-key path is never
		// reached by the current sole caller (FindMatchesForEvidence).
		return condition.Operator == "!="
	}
	matches := strings.EqualFold(value, condition.Value)
	if condition.Operator == "!=" {
		// todo[sonnet]: this code might be dead code. Left as part of the implementation design.
		// review if needed in the future and consider removing it.
		// SelectorLabelsToFilter only emits "=" operators; the "!=" present-key path is never
		// reached by the current sole caller (FindMatchesForEvidence).
		return !matches
	}
	return matches
}

// SelectorLabelsToFilter converts evidence template selector labels into a
// labelfilter.Filter with an AND query, mirroring the matching semantics used
// by GetEvidenceSearchByFilterQuery (all conditions must be satisfied).
//
// When selectors is empty, the returned Filter has a nil Scope. evaluateFilterInMemory
// treats a nil Scope as no-match (false), which is consistent with the empty-selector
// behavior. Empty selectors are rejected at write time (selectorLabels ≥ 1 enforced by
// validation), so this case should not occur on persisted templates.
func SelectorLabelsToFilter(selectors []EvidenceTemplateSelectorLabel) labelfilter.Filter {
	if len(selectors) == 0 {
		// todo[sonnet]: this code might be dead code. Left as part of the implementation design.
		// review if needed in the future and consider removing it.
		// Empty selectors are rejected at write time (selectorLabels ≥ 1 enforced by validation),
		// so persisted templates never reach this path via FindMatchesForEvidence.
		return labelfilter.Filter{}
	}

	scopes := make([]labelfilter.Scope, 0, len(selectors))
	for _, sel := range selectors {
		scopes = append(scopes, labelfilter.Scope{
			Condition: &labelfilter.Condition{
				Label:    sel.Key,
				Operator: "=",
				Value:    sel.Value,
			},
		})
	}

	return labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Query: &labelfilter.Query{
				Operator: "AND",
				Scopes:   scopes,
			},
		},
	}
}

func replaceEvidenceTemplateSelectorLabels(tx *gorm.DB, evidenceTemplateID uuid.UUID, labels []EvidenceTemplateSelectorLabelInput) error {
	if err := tx.Delete(&EvidenceTemplateSelectorLabel{}, "evidence_template_id = ?", evidenceTemplateID).Error; err != nil {
		return err
	}

	rows := make([]EvidenceTemplateSelectorLabel, 0, len(labels))
	for _, label := range labels {
		rows = append(rows, EvidenceTemplateSelectorLabel{
			EvidenceTemplateID: evidenceTemplateID,
			Key:                label.Key,
			Value:              label.Value,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return tx.Create(&rows).Error
}

func replaceEvidenceTemplateLabelSchema(tx *gorm.DB, evidenceTemplateID uuid.UUID, fields []EvidenceTemplateLabelSchemaFieldInput) error {
	if err := tx.Delete(&EvidenceTemplateLabelSchemaField{}, "evidence_template_id = ?", evidenceTemplateID).Error; err != nil {
		return err
	}

	rows := make([]EvidenceTemplateLabelSchemaField, 0, len(fields))
	for _, field := range fields {
		rows = append(rows, EvidenceTemplateLabelSchemaField{
			EvidenceTemplateID: evidenceTemplateID,
			Key:                field.Key,
			Description:        field.Description,
			Required:           field.Required,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return tx.Create(&rows).Error
}

func replaceEvidenceTemplateRiskLinks(tx *gorm.DB, evidenceTemplateID uuid.UUID, riskTemplateIDs []uuid.UUID) error {
	if err := tx.Delete(&EvidenceTemplateRiskTemplate{}, "evidence_template_id = ?", evidenceTemplateID).Error; err != nil {
		return err
	}

	rows := make([]EvidenceTemplateRiskTemplate, 0, len(riskTemplateIDs))
	for _, id := range riskTemplateIDs {
		rows = append(rows, EvidenceTemplateRiskTemplate{
			EvidenceTemplateID: evidenceTemplateID,
			RiskTemplateID:     id,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return tx.Create(&rows).Error
}

func replaceEvidenceTemplateSubjectLinks(tx *gorm.DB, evidenceTemplateID uuid.UUID, subjectTemplateIDs []uuid.UUID) error {
	if err := tx.Delete(&EvidenceTemplateSubjectTemplate{}, "evidence_template_id = ?", evidenceTemplateID).Error; err != nil {
		return err
	}

	rows := make([]EvidenceTemplateSubjectTemplate, 0, len(subjectTemplateIDs))
	for _, id := range subjectTemplateIDs {
		rows = append(rows, EvidenceTemplateSubjectTemplate{
			EvidenceTemplateID: evidenceTemplateID,
			SubjectTemplateID:  id,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return tx.Create(&rows).Error
}

func validateEvidenceTemplateLinkedIDs(tx *gorm.DB, riskTemplateIDs, subjectTemplateIDs []uuid.UUID) error {
	if len(riskTemplateIDs) > 0 {
		var count int64
		if err := tx.Model(&RiskTemplate{}).Where("id IN ?", riskTemplateIDs).Count(&count).Error; err != nil {
			return err
		}
		if count != int64(len(riskTemplateIDs)) {
			return newValidationError("one or more riskTemplateIds were not found")
		}
	}
	if len(subjectTemplateIDs) > 0 {
		var count int64
		if err := tx.Model(&SubjectTemplate{}).Where("id IN ?", subjectTemplateIDs).Count(&count).Error; err != nil {
			return err
		}
		if count != int64(len(subjectTemplateIDs)) {
			return newValidationError("one or more subjectTemplateIds were not found")
		}
	}
	return nil
}

func validateEvidenceTemplatePayload(payload *EvidenceTemplatePayload) error {
	if payload == nil {
		return newValidationError("payload is required")
	}

	normalizeEvidenceTemplatePayload(payload)

	if err := validateEvidenceTemplateRequiredText("pluginId", payload.PluginID); err != nil {
		return err
	}
	if err := validateEvidenceTemplateRequiredText("policyPackage", payload.PolicyPackage); err != nil {
		return err
	}
	if err := validateEvidenceTemplateRequiredText("title", payload.Title); err != nil {
		return err
	}
	if err := validateEvidenceTemplateOptionalText("description", &payload.Description); err != nil {
		return err
	}
	if err := validateEvidenceTemplateMethods(payload.Methods); err != nil {
		return err
	}
	if err := validateEvidenceTemplateSelectorLabelInputs(payload.SelectorLabels); err != nil {
		return err
	}
	if err := validateEvidenceTemplateLabelSchemaInputs(payload.LabelSchema); err != nil {
		return err
	}
	if err := validateMaxItems("riskTemplateIds", len(payload.RiskTemplateIDs), maxEvidenceTemplateRiskLinks); err != nil {
		return err
	}
	if err := validateMaxItems("subjectTemplateIds", len(payload.SubjectTemplateIDs), maxEvidenceTemplateSubjectLinks); err != nil {
		return err
	}
	if err := validateUniqueUUIDs("riskTemplateIds", payload.RiskTemplateIDs); err != nil {
		return err
	}
	if err := validateUniqueUUIDs("subjectTemplateIds", payload.SubjectTemplateIDs); err != nil {
		return err
	}

	return nil
}

func normalizeEvidenceTemplatePayload(payload *EvidenceTemplatePayload) {
	payload.PluginID = strings.TrimSpace(payload.PluginID)
	payload.PolicyPackage = strings.TrimSpace(payload.PolicyPackage)
	payload.Title = strings.TrimSpace(payload.Title)
	payload.Description = strings.TrimSpace(payload.Description)

	for i := range payload.Methods {
		payload.Methods[i] = normalizeEvidenceTemplateMethod(payload.Methods[i])
	}
	for i := range payload.SelectorLabels {
		payload.SelectorLabels[i].Key = strings.ToLower(strings.TrimSpace(payload.SelectorLabels[i].Key))
		payload.SelectorLabels[i].Value = strings.TrimSpace(payload.SelectorLabels[i].Value)
	}
	for i := range payload.LabelSchema {
		payload.LabelSchema[i].Key = strings.ToLower(strings.TrimSpace(payload.LabelSchema[i].Key))
		if payload.LabelSchema[i].Description != nil {
			normalized := strings.TrimSpace(*payload.LabelSchema[i].Description)
			payload.LabelSchema[i].Description = &normalized
		}
	}
}

func validateEvidenceTemplateMethods(methods []string) error {
	seen := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		if !isValidEvidenceTemplateMethod(m) {
			return newValidationError(fmt.Sprintf("invalid method %q: must be one of TEST, EXAMINE, INTERVIEW", m))
		}
		if _, exists := seen[m]; exists {
			return newValidationError("methods contains duplicate entries")
		}
		seen[m] = struct{}{}
	}
	return nil
}

func validateEvidenceTemplateSelectorLabelInputs(labels []EvidenceTemplateSelectorLabelInput) error {
	if err := validateMaxItems("selectorLabels", len(labels), maxEvidenceTemplateSelectorLabels); err != nil {
		return err
	}
	if len(labels) == 0 {
		return newValidationError("selectorLabels is required")
	}

	seen := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if err := validateEvidenceTemplateRequiredText("selectorLabels.key", label.Key); err != nil {
			return err
		}
		if err := validateEvidenceTemplateRequiredText("selectorLabels.value", label.Value); err != nil {
			return err
		}
		if _, exists := seen[label.Key]; exists {
			return newValidationError("selectorLabels contains duplicate keys")
		}
		seen[label.Key] = struct{}{}
	}

	return nil
}

func validateEvidenceTemplateLabelSchemaInputs(fields []EvidenceTemplateLabelSchemaFieldInput) error {
	if err := validateMaxItems("labelSchema", len(fields), maxEvidenceTemplateLabelSchema); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if err := validateEvidenceTemplateRequiredText("labelSchema.key", field.Key); err != nil {
			return err
		}
		if err := validateEvidenceTemplateOptionalText("labelSchema.description", field.Description); err != nil {
			return err
		}
		if _, exists := seen[field.Key]; exists {
			return newValidationError("labelSchema contains duplicate keys")
		}
		seen[field.Key] = struct{}{}
	}

	return nil
}

func validateUniqueUUIDs(field string, ids []uuid.UUID) error {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		if _, exists := seen[id]; exists {
			return newValidationError(fmt.Sprintf("%s contains duplicate IDs", field))
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateEvidenceTemplateRequiredText(field, value string) error {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return newValidationError(fmt.Sprintf("%s is required", field))
	}
	return validateEvidenceTemplateTextLength(field, normalized)
}

func validateEvidenceTemplateOptionalText(field string, value *string) error {
	if value == nil {
		return nil
	}
	normalized := strings.TrimSpace(*value)
	*value = normalized
	return validateEvidenceTemplateTextLength(field, normalized)
}

func validateEvidenceTemplateTextLength(field, value string) error {
	if utf8.RuneCountInString(value) > maxEvidenceTemplateFieldLength {
		return newValidationError(fmt.Sprintf("%s must be at most %d characters", field, maxEvidenceTemplateFieldLength))
	}
	return nil
}

func fetchEvidenceTemplateByID(db *gorm.DB, id uuid.UUID) (*EvidenceTemplate, error) {
	var row EvidenceTemplate
	if err := db.
		Preload("SelectorLabels", preloadEvidenceTemplateSelectorLabels).
		Preload("LabelSchema", preloadEvidenceTemplateLabelSchema).
		Preload("RiskTemplates").
		Preload("SubjectTemplates").
		First(&row, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func preloadEvidenceTemplateSelectorLabels(db *gorm.DB) *gorm.DB {
	return db.Order("key ASC")
}

func preloadEvidenceTemplateLabelSchema(db *gorm.DB) *gorm.DB {
	return db.Order("key ASC")
}
