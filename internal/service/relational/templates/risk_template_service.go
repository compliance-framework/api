package templates

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	maxRiskTemplateFieldLength = 1000
	maxThreatRefsPerTemplate   = 50
	maxViolationIDsPerTemplate = 100
	maxRemediationTasks        = 100
)

type ValidationError struct {
	message string
}

func (e ValidationError) Error() string {
	return e.message
}

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

func newValidationError(message string) error {
	return ValidationError{message: message}
}

type RiskTemplateService struct {
	db *gorm.DB
}

func NewRiskTemplateService(db *gorm.DB) *RiskTemplateService {
	return &RiskTemplateService{db: db}
}

type RiskTemplateListFilters struct {
	PluginID      *string
	PolicyPackage *string
	IsActive      *bool
}

type RiskTemplateListParams struct {
	Filters RiskTemplateListFilters
	Limit   int
	Offset  int
}

type ThreatRefInput struct {
	System     string
	ExternalID string
	Title      string
	URL        *string
}

type RemediationTaskInput struct {
	Title      string
	OrderIndex int
}

type RemediationTemplateInput struct {
	Title       string
	Description *string
	Tasks       []RemediationTaskInput
}

type RiskTemplatePayload struct {
	PluginID       string
	PolicyPackage  string
	Name           string
	Title          string
	Statement      string
	LikelihoodHint *string
	ImpactHint     *string
	ViolationIDs   []string
	IsActive       *bool
	ThreatRefs     []ThreatRefInput

	// Optional: nil means "no remediation template".
	RemediationTemplate *RemediationTemplateInput
}

func (s *RiskTemplateService) List(params RiskTemplateListParams) ([]RiskTemplate, int64, error) {
	query := s.db.Model(&RiskTemplate{})

	if params.Filters.PluginID != nil {
		pluginID := strings.TrimSpace(*params.Filters.PluginID)
		if pluginID != "" {
			query = query.Where("plugin_id = ?", pluginID)
		}
	}
	if params.Filters.PolicyPackage != nil {
		policyPackage := strings.ToLower(strings.TrimSpace(*params.Filters.PolicyPackage))
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

	var rows []RiskTemplate
	if err := query.
		Preload("ThreatRefs", preloadThreatRefs).
		Preload("RemediationTemplate").
		Preload("RemediationTemplate.Tasks", preloadRemediationTasks).
		Order("created_at desc").
		Limit(params.Limit).
		Offset(params.Offset).
		Find(&rows).Error; err != nil {
		return nil, 0, err
	}

	return rows, total, nil
}

func (s *RiskTemplateService) GetByID(id uuid.UUID) (*RiskTemplate, error) {
	return fetchRiskTemplateByID(s.db, id)
}

func (s *RiskTemplateService) Create(payload RiskTemplatePayload) (*RiskTemplate, error) {
	if err := validateRiskTemplatePayload(&payload); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	var remediationTemplateID *uuid.UUID
	if payload.RemediationTemplate != nil {
		remediation, err := upsertRemediationTemplate(tx, nil, payload.RemediationTemplate)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		remediationTemplateID = remediation.ID
	}

	row := RiskTemplate{
		PluginID:       payload.PluginID,
		PolicyPackage:  payload.PolicyPackage,
		Name:           payload.Name,
		Title:          payload.Title,
		Statement:      payload.Statement,
		LikelihoodHint: payload.LikelihoodHint,
		ImpactHint:     payload.ImpactHint,
		ViolationIDs:   datatypes.NewJSONSlice(payload.ViolationIDs),
		IsActive:       true,
	}
	if payload.IsActive != nil {
		row.IsActive = *payload.IsActive
	}
	if remediationTemplateID != nil {
		row.RemediationTemplateID = remediationTemplateID
	}

	if err := tx.Select(
		"ID",
		"CreatedAt",
		"UpdatedAt",
		"PluginID",
		"PolicyPackage",
		"Name",
		"Title",
		"Statement",
		"LikelihoodHint",
		"ImpactHint",
		"ViolationIDs",
		"IsActive",
		"RemediationTemplateID",
	).Create(&row).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if payload.IsActive != nil && !*payload.IsActive {
		// GORM applies the model default (`default:true`) for false booleans in this insert path
		// under Postgres. Force the persisted value so create behavior matches the API payload.
		if err := tx.Model(&RiskTemplate{}).Where("id = ?", *row.ID).Update("is_active", false).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	if err := replaceThreatRefs(tx, *row.ID, payload.ThreatRefs); err != nil {
		tx.Rollback()
		return nil, err
	}

	created, err := fetchRiskTemplateByID(tx, *row.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return created, nil
}

func (s *RiskTemplateService) Update(id uuid.UUID, payload RiskTemplatePayload) (*RiskTemplate, error) {
	if err := validateRiskTemplatePayload(&payload); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	var existing RiskTemplate
	if err := tx.Preload("RemediationTemplate").First(&existing, "id = ?", id).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	existing.PluginID = payload.PluginID
	existing.PolicyPackage = payload.PolicyPackage
	existing.Name = payload.Name
	existing.Title = payload.Title
	existing.Statement = payload.Statement
	existing.LikelihoodHint = payload.LikelihoodHint
	existing.ImpactHint = payload.ImpactHint
	existing.ViolationIDs = datatypes.NewJSONSlice(payload.ViolationIDs)
	if payload.IsActive != nil {
		existing.IsActive = *payload.IsActive
	}

	if payload.RemediationTemplate != nil {
		remediation, err := upsertRemediationTemplate(tx, existing.RemediationTemplateID, payload.RemediationTemplate)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		existing.RemediationTemplateID = remediation.ID
	} else if existing.RemediationTemplateID != nil {
		if err := deleteRemediationTemplateWithTasks(tx, *existing.RemediationTemplateID); err != nil {
			tx.Rollback()
			return nil, err
		}
		existing.RemediationTemplateID = nil
		existing.RemediationTemplate = nil
	}

	if err := tx.Omit("ThreatRefs", "RemediationTemplate").Save(&existing).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := replaceThreatRefs(tx, *existing.ID, payload.ThreatRefs); err != nil {
		tx.Rollback()
		return nil, err
	}

	updated, err := fetchRiskTemplateByID(tx, *existing.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return updated, nil
}

func (s *RiskTemplateService) Delete(id uuid.UUID) error {
	tx := s.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer rollbackTxOnPanic(tx)

	var existing RiskTemplate
	if err := tx.Select("id", "remediation_template_id").First(&existing, "id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Delete(&RiskTemplateThreatRef{}, "risk_template_id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Delete(&EvidenceTemplateRiskTemplate{}, "risk_template_id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Delete(&RiskTemplate{}, "id = ?", id).Error; err != nil {
		tx.Rollback()
		return err
	}

	if existing.RemediationTemplateID != nil {
		if err := deleteRemediationTemplateWithTasks(tx, *existing.RemediationTemplateID); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func (s *RiskTemplateService) ValidateViolationMatch(violationIDs []string, violationID string) bool {
	if len(violationIDs) == 0 {
		return true
	}

	normalizedCandidate := strings.TrimSpace(strings.ToLower(violationID))
	for _, id := range violationIDs {
		if strings.TrimSpace(strings.ToLower(id)) == normalizedCandidate {
			return true
		}
	}

	return false
}

func replaceThreatRefs(tx *gorm.DB, riskTemplateID uuid.UUID, refs []ThreatRefInput) error {
	if err := tx.Delete(&RiskTemplateThreatRef{}, "risk_template_id = ?", riskTemplateID).Error; err != nil {
		return err
	}

	rows := make([]RiskTemplateThreatRef, 0, len(refs))
	for _, ref := range refs {
		rows = append(rows, RiskTemplateThreatRef{
			RiskTemplateID: riskTemplateID,
			System:         ref.System,
			ExternalID:     ref.ExternalID,
			Title:          ref.Title,
			URL:            ref.URL,
		})
	}

	if len(rows) == 0 {
		return nil
	}

	return tx.Create(&rows).Error
}

func upsertRemediationTemplate(tx *gorm.DB, remediationTemplateID *uuid.UUID, input *RemediationTemplateInput) (*RemediationTemplate, error) {
	if input == nil {
		return nil, newValidationError("remediationTemplate is required")
	}

	var (
		row *RemediationTemplate
		err error
	)

	if remediationTemplateID != nil {
		row, err = updateRemediationTemplate(tx, *remediationTemplateID, input)
	} else {
		row, err = createRemediationTemplate(tx, input)
	}
	if err != nil {
		return nil, err
	}

	if err := replaceRemediationTasks(tx, *row.ID, input.Tasks); err != nil {
		return nil, err
	}

	return row, nil
}

func validateRiskTemplatePayload(payload *RiskTemplatePayload) error {
	if payload == nil {
		return newValidationError("payload is required")
	}

	normalizeRiskTemplatePayload(payload)

	if err := validateRequiredText("pluginId", payload.PluginID); err != nil {
		return err
	}
	if err := validateRequiredText("policyPackage", payload.PolicyPackage); err != nil {
		return err
	}
	if err := validateRequiredText("name", payload.Name); err != nil {
		return err
	}
	if err := validateRequiredText("title", payload.Title); err != nil {
		return err
	}
	if err := validateRequiredText("statement", payload.Statement); err != nil {
		return err
	}
	if err := validateOptionalRiskLevel("likelihoodHint", payload.LikelihoodHint); err != nil {
		return err
	}
	if err := validateOptionalRiskLevel("impactHint", payload.ImpactHint); err != nil {
		return err
	}
	if err := validateMaxItems("violationIds", len(payload.ViolationIDs), maxViolationIDsPerTemplate); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice("violationIds", payload.ViolationIDs); err != nil {
		return err
	}
	if err := validateStringSliceLength("violationIds", payload.ViolationIDs); err != nil {
		return err
	}
	if err := validateMaxItems("threatIds", len(payload.ThreatRefs), maxThreatRefsPerTemplate); err != nil {
		return err
	}
	if err := validateThreatRefs(payload.ThreatRefs); err != nil {
		return err
	}
	if err := validateRemediationTemplate(payload.RemediationTemplate); err != nil {
		return err
	}

	return nil
}

func rollbackTxOnPanic(tx *gorm.DB) {
	if r := recover(); r != nil {
		tx.Rollback()
		panic(r)
	}
}

func normalizeRiskTemplatePayload(payload *RiskTemplatePayload) {
	payload.PluginID = strings.TrimSpace(payload.PluginID)
	payload.PolicyPackage = strings.ToLower(strings.TrimSpace(payload.PolicyPackage))
	payload.Name = strings.TrimSpace(payload.Name)
	payload.Title = strings.TrimSpace(payload.Title)
	payload.Statement = strings.TrimSpace(payload.Statement)

	for i := range payload.ViolationIDs {
		payload.ViolationIDs[i] = strings.TrimSpace(payload.ViolationIDs[i])
	}

	for i := range payload.ThreatRefs {
		payload.ThreatRefs[i].System = strings.TrimSpace(payload.ThreatRefs[i].System)
		payload.ThreatRefs[i].ExternalID = strings.TrimSpace(payload.ThreatRefs[i].ExternalID)
		payload.ThreatRefs[i].Title = strings.TrimSpace(payload.ThreatRefs[i].Title)
		if payload.ThreatRefs[i].URL != nil {
			normalizedURL := strings.TrimSpace(*payload.ThreatRefs[i].URL)
			payload.ThreatRefs[i].URL = &normalizedURL
		}
	}

	if payload.RemediationTemplate == nil {
		return
	}

	payload.RemediationTemplate.Title = strings.TrimSpace(payload.RemediationTemplate.Title)
	if payload.RemediationTemplate.Description != nil {
		normalizedDescription := strings.TrimSpace(*payload.RemediationTemplate.Description)
		payload.RemediationTemplate.Description = &normalizedDescription
	}

	for i := range payload.RemediationTemplate.Tasks {
		payload.RemediationTemplate.Tasks[i].Title = strings.TrimSpace(payload.RemediationTemplate.Tasks[i].Title)
	}
}

func createRemediationTemplate(tx *gorm.DB, input *RemediationTemplateInput) (*RemediationTemplate, error) {
	row := RemediationTemplate{
		Title:       input.Title,
		Description: input.Description,
	}
	if err := tx.Create(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func updateRemediationTemplate(tx *gorm.DB, remediationTemplateID uuid.UUID, input *RemediationTemplateInput) (*RemediationTemplate, error) {
	var row RemediationTemplate
	if err := tx.First(&row, "id = ?", remediationTemplateID).Error; err != nil {
		return nil, err
	}
	row.Title = input.Title
	row.Description = input.Description
	if err := tx.Save(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func replaceRemediationTasks(tx *gorm.DB, remediationTemplateID uuid.UUID, input []RemediationTaskInput) error {
	if err := tx.Delete(&RemediationTask{}, "remediation_template_id = ?", remediationTemplateID).Error; err != nil {
		return err
	}

	tasks := make([]RemediationTask, 0, len(input))
	for _, task := range input {
		tasks = append(tasks, RemediationTask{
			RemediationTemplateID: remediationTemplateID,
			Title:                 task.Title,
			OrderIndex:            task.OrderIndex,
		})
	}
	if len(tasks) == 0 {
		return nil
	}

	return tx.Create(&tasks).Error
}

func deleteRemediationTemplateWithTasks(tx *gorm.DB, remediationTemplateID uuid.UUID) error {
	if err := tx.Delete(&RemediationTask{}, "remediation_template_id = ?", remediationTemplateID).Error; err != nil {
		return err
	}
	return tx.Delete(&RemediationTemplate{}, "id = ?", remediationTemplateID).Error
}

func validateThreatRefs(refs []ThreatRefInput) error {
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if err := validateRequiredText("threatIds.system", ref.System); err != nil {
			return err
		}
		if err := validateRequiredText("threatIds.id", ref.ExternalID); err != nil {
			return err
		}
		if err := validateRequiredText("threatIds.title", ref.Title); err != nil {
			return err
		}
		if err := validateOptionalText("threatIds.url", ref.URL); err != nil {
			return err
		}

		key := strings.TrimSpace(ref.System) + "|" + strings.TrimSpace(ref.ExternalID)
		if _, exists := seen[key]; exists {
			return newValidationError("threatIds contains duplicate system/id pairs")
		}
		seen[key] = struct{}{}
	}

	return nil
}

func validateRemediationTemplate(remediation *RemediationTemplateInput) error {
	if remediation == nil {
		return nil
	}

	if err := validateRequiredText("remediationTemplate.title", remediation.Title); err != nil {
		return err
	}
	if err := validateOptionalText("remediationTemplate.description", remediation.Description); err != nil {
		return err
	}
	if err := validateMaxItems("remediationTemplate.tasks", len(remediation.Tasks), maxRemediationTasks); err != nil {
		return err
	}

	seenOrder := make(map[int]struct{}, len(remediation.Tasks))
	for _, task := range remediation.Tasks {
		if err := validateRequiredText("remediationTemplate.tasks.title", task.Title); err != nil {
			return err
		}
		if task.OrderIndex <= 0 {
			return newValidationError("remediationTemplate.tasks.orderIndex must be greater than 0")
		}
		if _, exists := seenOrder[task.OrderIndex]; exists {
			return newValidationError("remediationTemplate.tasks.orderIndex must be unique")
		}
		seenOrder[task.OrderIndex] = struct{}{}
	}

	return nil
}

func validateRequiredText(field, value string) error {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return newValidationError(fmt.Sprintf("%s is required", field))
	}
	return validateTextLength(field, normalized)
}

func validateOptionalText(field string, value *string) error {
	if value == nil {
		return nil
	}
	normalized := strings.TrimSpace(*value)
	*value = normalized
	return validateTextLength(field, normalized)
}

func validateOptionalRiskLevel(field string, level *string) error {
	if level == nil {
		return nil
	}
	normalized := strings.TrimSpace(*level)
	*level = normalized
	if normalized == "" {
		return nil
	}
	if !riskrel.RiskLevel(normalized).IsValid() {
		return newValidationError(fmt.Sprintf("invalid %s", field))
	}
	return nil
}

func validateMaxItems(field string, size, max int) error {
	if size > max {
		return newValidationError(fmt.Sprintf("%s must contain at most %d items", field, max))
	}
	return nil
}

func validateStringSliceLength(field string, values []string) error {
	for _, value := range values {
		if err := validateTextLength(field, value); err != nil {
			return err
		}
	}
	return nil
}

func validateNonEmptyStringSlice(field string, values []string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return newValidationError(fmt.Sprintf("%s entries must be non-empty", field))
		}
	}
	return nil
}

func validateTextLength(field, value string) error {
	if utf8.RuneCountInString(value) > maxRiskTemplateFieldLength {
		return newValidationError(fmt.Sprintf("%s must be at most %d characters", field, maxRiskTemplateFieldLength))
	}
	return nil
}

func fetchRiskTemplateByID(db *gorm.DB, id uuid.UUID) (*RiskTemplate, error) {
	var row RiskTemplate
	if err := db.
		Preload("ThreatRefs", preloadThreatRefs).
		Preload("RemediationTemplate").
		Preload("RemediationTemplate.Tasks", preloadRemediationTasks).
		First(&row, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func preloadThreatRefs(db *gorm.DB) *gorm.DB {
	return db.Order("system ASC, external_id ASC")
}

func preloadRemediationTasks(db *gorm.DB) *gorm.DB {
	return db.Order("order_index ASC")
}

// BatchRiskTemplateItem is a single item in a batch upsert request.
// PluginID and PolicyPackage are inherited from the batch-level scope and must not be set here.
// ID is mandatory and must be provided by the caller (agent-side UUID generation).
type BatchRiskTemplateItem struct {
	ID                  uuid.UUID
	Name                string
	Title               string
	Statement           string
	LikelihoodHint      *string
	ImpactHint          *string
	ViolationIDs        []string
	IsActive            *bool
	ThreatRefs          []ThreatRefInput
	RemediationTemplate *RemediationTemplateInput
}

// BatchUpsertRiskTemplatesResult is the result of a RiskTemplateService.BatchUpsert call.
type BatchUpsertRiskTemplatesResult struct {
	Created   []RiskTemplate
	Updated   []RiskTemplate
	Deleted   []uuid.UUID
	Unchanged []uuid.UUID
}

// BatchUpsert reconciles the full set of risk templates for a given (pluginID, policyPackage) pair.
// It creates, updates, and deletes templates as needed in a single atomic transaction.
// Templates not present in the payload are always deleted.
func (s *RiskTemplateService) BatchUpsert(pluginID, policyPackage string, items []BatchRiskTemplateItem) (*BatchUpsertRiskTemplatesResult, error) {
	pluginID = strings.TrimSpace(pluginID)
	policyPackage = strings.ToLower(strings.TrimSpace(policyPackage))

	if err := validateRequiredText("pluginId", pluginID); err != nil {
		return nil, err
	}
	if err := validateRequiredText("policyPackage", policyPackage); err != nil {
		return nil, err
	}

	// Validate that all items carry a non-nil, unique ID supplied by the caller.
	type resolvedItem struct {
		id   uuid.UUID
		item BatchRiskTemplateItem
	}
	resolved := make([]resolvedItem, 0, len(items))
	seen := make(map[uuid.UUID]struct{}, len(items))
	for i, item := range items {
		if item.ID == uuid.Nil {
			return nil, newValidationError(fmt.Sprintf("item %d: id is required", i))
		}
		if _, dup := seen[item.ID]; dup {
			return nil, newValidationError(fmt.Sprintf("item %d: duplicate id %s", i, item.ID))
		}
		seen[item.ID] = struct{}{}
		resolved = append(resolved, resolvedItem{id: item.ID, item: item})
	}

	// Validate all payloads before opening the transaction.
	for i, r := range resolved {
		payload := batchItemToPayload(pluginID, policyPackage, r.item)
		if err := validateRiskTemplatePayload(&payload); err != nil {
			return nil, fmt.Errorf("item %d (id %s): %w", i, r.id, err)
		}
		resolved[i].item = batchItemFromPayload(r.item, payload)
	}

	payloadIDs := make(map[uuid.UUID]struct{}, len(resolved))
	for _, r := range resolved {
		payloadIDs[r.id] = struct{}{}
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	// Load existing templates inside the transaction so the read and all subsequent
	// mutations are part of the same consistent snapshot, eliminating the race window
	// between a pre-tx read and the tx writes.
	var existingRows []RiskTemplate
	if err := tx.
		Where("plugin_id = ? AND policy_package = ?", pluginID, policyPackage).
		Preload("ThreatRefs", preloadThreatRefs).
		Preload("RemediationTemplate").
		Preload("RemediationTemplate.Tasks", preloadRemediationTasks).
		Find(&existingRows).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	existingByID := make(map[uuid.UUID]RiskTemplate, len(existingRows))
	for _, row := range existingRows {
		existingByID[*row.ID] = row
	}

	result := &BatchUpsertRiskTemplatesResult{
		Created:   make([]RiskTemplate, 0),
		Updated:   make([]RiskTemplate, 0),
		Deleted:   make([]uuid.UUID, 0),
		Unchanged: make([]uuid.UUID, 0),
	}

	// Create or update.
	for _, r := range resolved {
		payload := batchItemToPayload(pluginID, policyPackage, r.item)
		if existing, exists := existingByID[r.id]; exists {
			if riskTemplateMatchesPayload(existing, payload) {
				result.Unchanged = append(result.Unchanged, r.id)
				continue
			}
			row, err := updateRiskTemplateInTx(tx, r.id, payload)
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("update risk template %s: %w", r.id, err)
			}
			result.Updated = append(result.Updated, *row)
		} else {
			// Guard against ID collisions with templates outside this (plugin, policy) scope.
			var count int64
			if err := tx.Model(&RiskTemplate{}).Where("id = ?", r.id).Count(&count).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
			if count > 0 {
				tx.Rollback()
				return nil, newValidationError(fmt.Sprintf("id %s already exists in a different scope", r.id))
			}
			row, err := createRiskTemplateInTx(tx, r.id, payload)
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("create risk template %s: %w", r.id, err)
			}
			result.Created = append(result.Created, *row)
		}
	}

	// Delete
	for id := range existingByID {
		if _, inPayload := payloadIDs[id]; inPayload {
			continue
		}

		existing := existingByID[id]
		if err := tx.Delete(&RiskTemplateThreatRef{}, "risk_template_id = ?", id).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("delete threat refs for risk template %s: %w", id, err)
		}
		if err := tx.Delete(&EvidenceTemplateRiskTemplate{}, "risk_template_id = ?", id).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("delete evidence links for risk template %s: %w", id, err)
		}
		if err := tx.Delete(&RiskTemplate{}, "id = ?", id).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("delete risk template %s: %w", id, err)
		}
		if existing.RemediationTemplateID != nil {
			if err := deleteRemediationTemplateWithTasks(tx, *existing.RemediationTemplateID); err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("delete remediation for risk template %s: %w", id, err)
			}
		}
		result.Deleted = append(result.Deleted, id)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return result, nil
}

// batchItemToPayload converts a BatchRiskTemplateItem to a RiskTemplatePayload.
// The returned payload is NOT yet validated or normalised; call validateRiskTemplatePayload first.
func batchItemToPayload(pluginID, policyPackage string, item BatchRiskTemplateItem) RiskTemplatePayload {
	return RiskTemplatePayload{
		PluginID:            pluginID,
		PolicyPackage:       policyPackage,
		Name:                item.Name,
		Title:               item.Title,
		Statement:           item.Statement,
		LikelihoodHint:      item.LikelihoodHint,
		ImpactHint:          item.ImpactHint,
		ViolationIDs:        append([]string{}, item.ViolationIDs...),
		IsActive:            item.IsActive,
		ThreatRefs:          append([]ThreatRefInput{}, item.ThreatRefs...),
		RemediationTemplate: item.RemediationTemplate,
	}
}

// batchItemFromPayload copies normalised payload fields back into the item so that the
// normalised values are used when the item is processed again.
func batchItemFromPayload(item BatchRiskTemplateItem, payload RiskTemplatePayload) BatchRiskTemplateItem {
	item.Name = payload.Name
	item.Title = payload.Title
	item.Statement = payload.Statement
	item.LikelihoodHint = payload.LikelihoodHint
	item.ImpactHint = payload.ImpactHint
	item.ViolationIDs = payload.ViolationIDs
	item.IsActive = payload.IsActive
	item.ThreatRefs = payload.ThreatRefs
	item.RemediationTemplate = payload.RemediationTemplate
	return item
}

// createRiskTemplateInTx creates a risk template within an existing transaction using the given id.
func createRiskTemplateInTx(tx *gorm.DB, id uuid.UUID, payload RiskTemplatePayload) (*RiskTemplate, error) {
	var remediationTemplateID *uuid.UUID
	if payload.RemediationTemplate != nil {
		remediation, err := upsertRemediationTemplate(tx, nil, payload.RemediationTemplate)
		if err != nil {
			return nil, err
		}
		remediationTemplateID = remediation.ID
	}

	row := RiskTemplate{
		PluginID:       payload.PluginID,
		PolicyPackage:  payload.PolicyPackage,
		Name:           payload.Name,
		Title:          payload.Title,
		Statement:      payload.Statement,
		LikelihoodHint: payload.LikelihoodHint,
		ImpactHint:     payload.ImpactHint,
		ViolationIDs:   datatypes.NewJSONSlice(payload.ViolationIDs),
		IsActive:       true,
	}
	row.ID = &id
	if payload.IsActive != nil {
		row.IsActive = *payload.IsActive
	}
	if remediationTemplateID != nil {
		row.RemediationTemplateID = remediationTemplateID
	}

	if err := tx.Select(
		"ID",
		"CreatedAt",
		"UpdatedAt",
		"PluginID",
		"PolicyPackage",
		"Name",
		"Title",
		"Statement",
		"LikelihoodHint",
		"ImpactHint",
		"ViolationIDs",
		"IsActive",
		"RemediationTemplateID",
	).Create(&row).Error; err != nil {
		return nil, err
	}
	if err := replaceThreatRefs(tx, id, payload.ThreatRefs); err != nil {
		return nil, err
	}

	return fetchRiskTemplateByID(tx, id)
}

// updateRiskTemplateInTx updates an existing risk template within an existing transaction.
func updateRiskTemplateInTx(tx *gorm.DB, id uuid.UUID, payload RiskTemplatePayload) (*RiskTemplate, error) {
	var existing RiskTemplate
	if err := tx.Preload("RemediationTemplate").First(&existing, "id = ?", id).Error; err != nil {
		return nil, err
	}

	existing.PluginID = payload.PluginID
	existing.PolicyPackage = payload.PolicyPackage
	existing.Name = payload.Name
	existing.Title = payload.Title
	existing.Statement = payload.Statement
	existing.LikelihoodHint = payload.LikelihoodHint
	existing.ImpactHint = payload.ImpactHint
	existing.ViolationIDs = datatypes.NewJSONSlice(payload.ViolationIDs)
	if payload.IsActive != nil {
		existing.IsActive = *payload.IsActive
	}

	if payload.RemediationTemplate != nil {
		remediation, err := upsertRemediationTemplate(tx, existing.RemediationTemplateID, payload.RemediationTemplate)
		if err != nil {
			return nil, err
		}
		existing.RemediationTemplateID = remediation.ID
	} else if existing.RemediationTemplateID != nil {
		if err := deleteRemediationTemplateWithTasks(tx, *existing.RemediationTemplateID); err != nil {
			return nil, err
		}
		existing.RemediationTemplateID = nil
		existing.RemediationTemplate = nil
	}

	if err := tx.Omit("ThreatRefs", "RemediationTemplate").Save(&existing).Error; err != nil {
		return nil, err
	}

	if err := replaceThreatRefs(tx, *existing.ID, payload.ThreatRefs); err != nil {
		return nil, err
	}

	return fetchRiskTemplateByID(tx, *existing.ID)
}

// riskTemplateFP is an unexported fingerprint struct used to detect whether a batch
// payload differs from a stored template, avoiding unnecessary UPDATE statements.
type riskTemplateFP struct {
	Name           string     `json:"n"`
	Title          string     `json:"t"`
	Statement      string     `json:"s"`
	LikelihoodHint *string    `json:"lh,omitempty"`
	ImpactHint     *string    `json:"ih,omitempty"`
	IsActive       bool       `json:"ia"`
	ViolationIDs   []string   `json:"v"`
	ThreatRefs     []threatFP `json:"tr"`
	Remediation    *remFP     `json:"r,omitempty"`
}

type threatFP struct {
	System     string  `json:"s"`
	ExternalID string  `json:"e"`
	Title      string  `json:"t"`
	URL        *string `json:"u,omitempty"`
}

type remFP struct {
	Title       string   `json:"t"`
	Description *string  `json:"d,omitempty"`
	Tasks       []taskFP `json:"tasks"`
}

type taskFP struct {
	Title      string `json:"t"`
	OrderIndex int    `json:"o"`
}

// riskTemplateMatchesPayload returns true when the stored template already reflects
// every field in the payload, so no UPDATE is necessary.
func riskTemplateMatchesPayload(existing RiskTemplate, payload RiskTemplatePayload) bool {
	a := riskTemplateFPFromExisting(existing)
	b := riskTemplateFPFromPayload(payload)
	if payload.IsActive == nil {
		b.IsActive = existing.IsActive
	}
	aj, err1 := json.Marshal(a)
	bj, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(aj) == string(bj)
}

func riskTemplateFPFromExisting(t RiskTemplate) riskTemplateFP {
	violations := make([]string, len(t.ViolationIDs))
	copy(violations, t.ViolationIDs)
	sort.Strings(violations)

	refs := make([]threatFP, 0, len(t.ThreatRefs))
	for _, r := range t.ThreatRefs {
		refs = append(refs, threatFP{System: r.System, ExternalID: r.ExternalID, Title: r.Title, URL: r.URL})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].System != refs[j].System {
			return refs[i].System < refs[j].System
		}
		return refs[i].ExternalID < refs[j].ExternalID
	})

	fp := riskTemplateFP{
		Name:           t.Name,
		Title:          t.Title,
		Statement:      t.Statement,
		LikelihoodHint: t.LikelihoodHint,
		ImpactHint:     t.ImpactHint,
		IsActive:       t.IsActive,
		ViolationIDs:   violations,
		ThreatRefs:     refs,
	}
	if t.RemediationTemplate != nil {
		tasks := make([]taskFP, 0, len(t.RemediationTemplate.Tasks))
		for _, task := range t.RemediationTemplate.Tasks {
			tasks = append(tasks, taskFP{Title: task.Title, OrderIndex: task.OrderIndex})
		}
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].OrderIndex < tasks[j].OrderIndex })
		fp.Remediation = &remFP{
			Title:       t.RemediationTemplate.Title,
			Description: t.RemediationTemplate.Description,
			Tasks:       tasks,
		}
	}
	return fp
}

func riskTemplateFPFromPayload(payload RiskTemplatePayload) riskTemplateFP {
	isActive := true
	if payload.IsActive != nil {
		isActive = *payload.IsActive
	}

	violations := make([]string, len(payload.ViolationIDs))
	copy(violations, payload.ViolationIDs)
	sort.Strings(violations)

	refs := make([]threatFP, 0, len(payload.ThreatRefs))
	for _, r := range payload.ThreatRefs {
		refs = append(refs, threatFP(r))
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].System != refs[j].System {
			return refs[i].System < refs[j].System
		}
		return refs[i].ExternalID < refs[j].ExternalID
	})

	fp := riskTemplateFP{
		Name:           payload.Name,
		Title:          payload.Title,
		Statement:      payload.Statement,
		LikelihoodHint: payload.LikelihoodHint,
		ImpactHint:     payload.ImpactHint,
		IsActive:       isActive,
		ViolationIDs:   violations,
		ThreatRefs:     refs,
	}
	if payload.RemediationTemplate != nil {
		tasks := make([]taskFP, 0, len(payload.RemediationTemplate.Tasks))
		for _, task := range payload.RemediationTemplate.Tasks {
			tasks = append(tasks, taskFP(task))
		}
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].OrderIndex < tasks[j].OrderIndex })
		fp.Remediation = &remFP{
			Title:       payload.RemediationTemplate.Title,
			Description: payload.RemediationTemplate.Description,
			Tasks:       tasks,
		}
	}
	return fp
}
