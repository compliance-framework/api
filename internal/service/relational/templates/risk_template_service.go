package templates

import (
	"errors"
	"fmt"
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
	payload.PolicyPackage = strings.TrimSpace(payload.PolicyPackage)
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
