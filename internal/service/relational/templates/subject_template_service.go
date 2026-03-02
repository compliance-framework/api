package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	subjectTemplateTypeInventoryItem = "inventory-item"
	subjectTemplateTypeComponent     = "component"
	subjectTemplateTypeUser          = "user"
	subjectTemplateTypeLocation      = "location"
	subjectTemplateTypeParty         = "party"
	subjectTemplateTypeResource      = "resource"

	subjectTemplateSourceModePolicyDerived  = "policy-derived"
	subjectTemplateSourceModeRuntimeDerived = "runtime-derived"

	maxSubjectTemplateFieldLength      = maxRiskTemplateFieldLength
	maxSubjectTemplateIdentityKeys     = 20
	maxSubjectTemplateSelectorLabels   = 50
	maxSubjectTemplateLabelSchemaItems = 100
	maxRuntimeComponentTemplatesScan   = 200
)

var allowedSubjectTemplateTypes = map[string]struct{}{
	subjectTemplateTypeInventoryItem: {},
	subjectTemplateTypeComponent:     {},
	subjectTemplateTypeUser:          {},
	subjectTemplateTypeLocation:      {},
	subjectTemplateTypeParty:         {},
	subjectTemplateTypeResource:      {},
}

var allowedSubjectTemplateSourceModes = map[string]struct{}{
	subjectTemplateSourceModePolicyDerived:  {},
	subjectTemplateSourceModeRuntimeDerived: {},
}

func NormalizeSubjectTemplateType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func IsValidSubjectTemplateType(value string) bool {
	normalized := NormalizeSubjectTemplateType(value)
	_, ok := allowedSubjectTemplateTypes[normalized]
	return ok
}

func NormalizeSubjectTemplateSourceMode(value string) string {
	return NormalizeSubjectTemplateType(value)
}

func IsValidSubjectTemplateSourceMode(value string) bool {
	normalized := NormalizeSubjectTemplateSourceMode(value)
	_, ok := allowedSubjectTemplateSourceModes[normalized]
	return ok
}

type SubjectTemplateService struct {
	db *gorm.DB
}

func NewSubjectTemplateService(db *gorm.DB) *SubjectTemplateService {
	return &SubjectTemplateService{db: db}
}

type SubjectTemplateListFilters struct {
	Type       *string
	SourceMode *string
}

type SubjectTemplateListParams struct {
	Filters SubjectTemplateListFilters
	Limit   int
	Offset  int
}

type SubjectTemplateSelectorLabelInput struct {
	Key   string
	Value string
}

type SubjectTemplateLabelSchemaFieldInput struct {
	Key         string
	Description *string
}

type SubjectTemplatePayload struct {
	Name              string
	Type              string
	IdentityLabelKeys []string
	Props             []relational.Prop
	Links             []relational.Link
	SourceMode        string
	SelectorLabels    []SubjectTemplateSelectorLabelInput
	LabelSchema       []SubjectTemplateLabelSchemaFieldInput
}

// TODO[codex-5-3-high]: Currently not wired to runtime evidence ingestion or assessment orchestration.
// Re-evaluate and remove if subject-template resolver integration is superseded.
type ResolveOrUpsertAssessmentSubjectInput struct {
	SubjectTemplateID uuid.UUID
	EvidenceLabels    []relational.Labels
}

// TODO[codex-5-3-high]: Currently not wired to runtime evidence ingestion.
// Re-evaluate and remove if component-template resolver integration is superseded.
type ResolveOrUpsertSystemComponentInput struct {
	SubjectTemplateID    uuid.UUID
	SystemSecurityPlanID uuid.UUID
	EvidenceLabels       []relational.Labels
}

// TODO[codex-5-3-high]: Currently not wired to runtime evidence ingestion.
// Re-evaluate and remove if component-template resolver integration is superseded.
type ResolveOrUpsertSystemComponentsForEvidenceInput struct {
	SystemSecurityPlanID uuid.UUID
	EvidenceLabels       []relational.Labels
}

type identityLabelPair struct {
	Key   string
	Value string
}

// TODO[codex-5-3-high]: Internal adapter for unresolved subject-template wiring.
// Remove with resolver path if unused by future integration.
type assessmentSubjectRow struct {
	relational.UUIDModel
	SSPID       *uuid.UUID                           `gorm:"column:sspid;type:uuid;index"`
	Type        string                               `gorm:"column:type"`
	Description *string                              `gorm:"column:description"`
	Remarks     *string                              `gorm:"column:remarks"`
	Props       datatypes.JSONSlice[relational.Prop] `gorm:"column:props;type:jsonb"`
	Links       datatypes.JSONSlice[relational.Link] `gorm:"column:links;type:jsonb"`
}

func (assessmentSubjectRow) TableName() string {
	return "assessment_subjects"
}

// TODO[codex-5-3-high]: Internal adapter for unresolved component-template wiring.
// Remove with resolver path if unused by future integration.
type systemComponentRow struct {
	relational.UUIDModel
	Type                   string                               `gorm:"column:type"`
	Title                  string                               `gorm:"column:title"`
	Description            string                               `gorm:"column:description"`
	Purpose                string                               `gorm:"column:purpose"`
	Remarks                string                               `gorm:"column:remarks"`
	Props                  datatypes.JSONSlice[relational.Prop] `gorm:"column:props;type:jsonb"`
	Links                  datatypes.JSONSlice[relational.Link] `gorm:"column:links;type:jsonb"`
	SystemImplementationID uuid.UUID                            `gorm:"column:system_implementation_id;type:uuid"`
}

func (systemComponentRow) TableName() string {
	return "system_components"
}

func (s *SubjectTemplateService) List(params SubjectTemplateListParams) ([]SubjectTemplate, int64, error) {
	query := s.db.Model(&SubjectTemplate{})

	if params.Filters.Type != nil {
		normalizedType := NormalizeSubjectTemplateType(*params.Filters.Type)
		if normalizedType != "" {
			query = query.Where("type = ?", normalizedType)
		}
	}
	if params.Filters.SourceMode != nil {
		normalizedSourceMode := NormalizeSubjectTemplateSourceMode(*params.Filters.SourceMode)
		if normalizedSourceMode != "" {
			query = query.Where("source_mode = ?", normalizedSourceMode)
		}
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []SubjectTemplate
	if err := query.
		Preload("SelectorLabels", preloadSubjectTemplateSelectorLabels).
		Preload("LabelSchema", preloadSubjectTemplateLabelSchema).
		Order("created_at desc").
		Limit(params.Limit).
		Offset(params.Offset).
		Find(&rows).Error; err != nil {
		return nil, 0, err
	}

	return rows, total, nil
}

func (s *SubjectTemplateService) GetByID(id uuid.UUID) (*SubjectTemplate, error) {
	return fetchSubjectTemplateByID(s.db, id)
}

func (s *SubjectTemplateService) Create(payload SubjectTemplatePayload) (*SubjectTemplate, error) {
	if err := validateSubjectTemplatePayload(&payload); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	row := SubjectTemplate{
		Name:              payload.Name,
		Type:              payload.Type,
		IdentityLabelKeys: datatypes.NewJSONSlice(payload.IdentityLabelKeys),
		Props:             datatypes.NewJSONSlice(payload.Props),
		Links:             datatypes.NewJSONSlice(payload.Links),
		SourceMode:        payload.SourceMode,
	}

	if err := tx.Select(
		"ID",
		"CreatedAt",
		"UpdatedAt",
		"Name",
		"Type",
		"IdentityLabelKeys",
		"Props",
		"Links",
		"SourceMode",
	).Create(&row).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := replaceSubjectTemplateSelectorLabels(tx, *row.ID, payload.SelectorLabels); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceSubjectTemplateLabelSchema(tx, *row.ID, payload.LabelSchema); err != nil {
		tx.Rollback()
		return nil, err
	}

	created, err := fetchSubjectTemplateByID(tx, *row.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return created, nil
}

func (s *SubjectTemplateService) Update(id uuid.UUID, payload SubjectTemplatePayload) (*SubjectTemplate, error) {
	if err := validateSubjectTemplatePayload(&payload); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	var existing SubjectTemplate
	if err := tx.First(&existing, "id = ?", id).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	existing.Name = payload.Name
	existing.Type = payload.Type
	existing.IdentityLabelKeys = datatypes.NewJSONSlice(payload.IdentityLabelKeys)
	existing.Props = datatypes.NewJSONSlice(payload.Props)
	existing.Links = datatypes.NewJSONSlice(payload.Links)
	existing.SourceMode = payload.SourceMode

	if err := tx.Omit("SelectorLabels", "LabelSchema").Save(&existing).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := replaceSubjectTemplateSelectorLabels(tx, *existing.ID, payload.SelectorLabels); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := replaceSubjectTemplateLabelSchema(tx, *existing.ID, payload.LabelSchema); err != nil {
		tx.Rollback()
		return nil, err
	}

	updated, err := fetchSubjectTemplateByID(tx, *existing.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return updated, nil
}

// TODO[codex-5-3-high]: This resolver is intentionally staged ahead of assessment-layer wiring.
// Remove if final architecture no longer calls through subject templates for assessment-subject lifecycle.
// Identity labels are persisted in assessment_subject_labels; returned AssessmentSubject does not include labels.
func (s *SubjectTemplateService) ResolveOrUpsertAssessmentSubject(input ResolveOrUpsertAssessmentSubjectInput) (*relational.AssessmentSubject, error) {
	if err := validateResolveOrUpsertAssessmentSubjectInput(input); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	template, err := fetchSubjectTemplateByID(tx, input.SubjectTemplateID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	identityPairs, err := projectIdentityLabelPairs(template.IdentityLabelKeys, input.EvidenceLabels)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	identityHash := buildEntityIdentityHash(template.Type, identityPairs)
	existingSubjectID, err := findAssessmentSubjectIDByIdentityHash(tx, template.Type, identityHash)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if existingSubjectID == nil {
		existingSubjectID, err = findAssessmentSubjectIDByLabelSet(tx, template.Type, identityPairs)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		if existingSubjectID != nil {
			identity := AssessmentSubjectIdentity{
				EntityType:          template.Type,
				IdentityHash:        identityHash,
				AssessmentSubjectID: *existingSubjectID,
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}
	}
	if existingSubjectID != nil {
		existingSubject, fetchErr := fetchAssessmentSubjectByID(tx, *existingSubjectID)
		if fetchErr != nil {
			if errors.Is(fetchErr, gorm.ErrRecordNotFound) {
				if err := deleteStaleAssessmentSubjectIdentity(tx, template.Type, identityHash, *existingSubjectID); err != nil {
					tx.Rollback()
					return nil, err
				}
				existingSubjectID = nil
			} else {
				tx.Rollback()
				return nil, fetchErr
			}
		}
		if existingSubjectID != nil {
			if err := tx.Commit().Error; err != nil {
				return nil, err
			}
			return existingSubject.toAssessmentSubject(), nil
		}
	}

	newSubject := assessmentSubjectRow{
		Type:  template.Type,
		Props: datatypes.NewJSONSlice(append([]relational.Prop{}, template.Props...)),
		Links: datatypes.NewJSONSlice(append([]relational.Link{}, template.Links...)),
	}
	if err := tx.Table(newSubject.TableName()).Create(&newSubject).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	labels := make([]riskrel.AssessmentSubjectLabel, 0, len(identityPairs))
	for _, pair := range identityPairs {
		labels = append(labels, riskrel.AssessmentSubjectLabel{
			AssessmentSubjectID: *newSubject.ID,
			Key:                 pair.Key,
			Value:               pair.Value,
		})
	}
	if len(labels) > 0 {
		if err := tx.Create(&labels).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	identity := AssessmentSubjectIdentity{
		EntityType:          template.Type,
		IdentityHash:        identityHash,
		AssessmentSubjectID: *newSubject.ID,
	}
	insertIdentity := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity)
	if insertIdentity.Error != nil {
		tx.Rollback()
		return nil, insertIdentity.Error
	}
	if insertIdentity.RowsAffected == 0 {
		if err := tx.Delete(&riskrel.AssessmentSubjectLabel{}, "assessment_subject_id = ?", *newSubject.ID).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
		if err := tx.Table(newSubject.TableName()).Delete(&assessmentSubjectRow{}, "id = ?", *newSubject.ID).Error; err != nil {
			tx.Rollback()
			return nil, err
		}

		existingSubjectID, err = findAssessmentSubjectIDByIdentityHash(tx, template.Type, identityHash)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		if existingSubjectID == nil {
			tx.Rollback()
			return nil, errors.New("failed to resolve subject identity")
		}

		existingSubject, fetchErr := fetchAssessmentSubjectByID(tx, *existingSubjectID)
		if fetchErr != nil {
			tx.Rollback()
			return nil, fetchErr
		}
		if err := tx.Commit().Error; err != nil {
			return nil, err
		}
		return existingSubject.toAssessmentSubject(), nil
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return newSubject.toAssessmentSubject(), nil
}

// TODO[codex-5-3-high]: This matcher is intentionally staged ahead of evidence-ingestion wiring.
// Remove if component lifecycle is implemented through a different path.
func (s *SubjectTemplateService) ResolveOrUpsertSystemComponentsForEvidence(input ResolveOrUpsertSystemComponentsForEvidenceInput) ([]relational.SystemComponent, error) {
	if input.SystemSecurityPlanID == uuid.Nil {
		return nil, newValidationError("systemSecurityPlanId is required")
	}
	if len(input.EvidenceLabels) == 0 {
		return []relational.SystemComponent{}, nil
	}

	labelsByKey, err := buildEvidenceLabelMap(input.EvidenceLabels)
	if err != nil {
		return nil, err
	}

	var templates []SubjectTemplate
	if err := s.db.
		Where("type = ? AND source_mode = ?", subjectTemplateTypeComponent, subjectTemplateSourceModeRuntimeDerived).
		Preload("SelectorLabels", preloadSubjectTemplateSelectorLabels).
		Order("created_at asc").
		Limit(maxRuntimeComponentTemplatesScan + 1).
		Find(&templates).Error; err != nil {
		return nil, err
	}
	if len(templates) > maxRuntimeComponentTemplatesScan {
		return nil, fmt.Errorf(
			"resolve system components reached scan limit of %d runtime-derived component subject templates; results may be incomplete",
			maxRuntimeComponentTemplatesScan,
		)
	}

	components := make([]relational.SystemComponent, 0, len(templates))
	seen := make(map[uuid.UUID]struct{}, len(templates))
	for _, template := range templates {
		if !matchesSubjectTemplateSelectorLabels(template.SelectorLabels, labelsByKey) {
			continue
		}
		if !hasAllIdentityLabelKeys(template.IdentityLabelKeys, labelsByKey) {
			continue
		}

		component, err := s.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
			SubjectTemplateID:    *template.ID,
			SystemSecurityPlanID: input.SystemSecurityPlanID,
			EvidenceLabels:       input.EvidenceLabels,
		})
		if err != nil {
			return nil, err
		}
		if component == nil || component.ID == nil {
			continue
		}
		if _, exists := seen[*component.ID]; exists {
			continue
		}

		seen[*component.ID] = struct{}{}
		components = append(components, *component)
	}

	return components, nil
}

// TODO[codex-5-3-high]: This resolver is intentionally staged ahead of evidence-ingestion wiring.
// Remove if component lifecycle is implemented through a different path.
func (s *SubjectTemplateService) ResolveOrUpsertSystemComponent(input ResolveOrUpsertSystemComponentInput) (*relational.SystemComponent, error) {
	if err := validateResolveOrUpsertSystemComponentInput(input); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	template, err := fetchSubjectTemplateByID(tx, input.SubjectTemplateID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if template.Type != subjectTemplateTypeComponent {
		tx.Rollback()
		return nil, newValidationError("subject template type must be component")
	}
	systemImplementationID, err := findSystemImplementationIDBySystemSecurityPlanID(tx, input.SystemSecurityPlanID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	identityPairs, err := projectIdentityLabelPairs(template.IdentityLabelKeys, input.EvidenceLabels)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	identityHash := buildEntityIdentityHash(template.Type, identityPairs)
	existingComponentID, err := findSystemComponentIDByIdentityHash(tx, template.Type, identityHash, systemImplementationID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if existingComponentID == nil {
		existingComponentID, err = findSystemComponentIDByLabelSet(tx, template.Type, identityPairs, systemImplementationID)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		if existingComponentID != nil {
			identity := SystemComponentIdentity{
				EntityType:             template.Type,
				IdentityHash:           identityHash,
				SystemImplementationID: systemImplementationID,
				SystemComponentID:      *existingComponentID,
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}
	}
	if existingComponentID != nil {
		existingComponent, fetchErr := fetchSystemComponentByID(tx, *existingComponentID)
		if fetchErr != nil {
			if errors.Is(fetchErr, gorm.ErrRecordNotFound) {
				if err := deleteStaleSystemComponentIdentity(tx, template.Type, identityHash, systemImplementationID); err != nil {
					tx.Rollback()
					return nil, err
				}
				existingComponentID = nil
			} else {
				tx.Rollback()
				return nil, fetchErr
			}
		}
		if existingComponentID != nil {
			if err := tx.Commit().Error; err != nil {
				return nil, err
			}
			return existingComponent.toSystemComponent(), nil
		}
	}

	newComponent := systemComponentRow{
		Type:                   template.Type,
		Title:                  template.Name,
		Props:                  datatypes.NewJSONSlice(append([]relational.Prop{}, template.Props...)),
		Links:                  datatypes.NewJSONSlice(append([]relational.Link{}, template.Links...)),
		Description:            "",
		Purpose:                "",
		Remarks:                "",
		SystemImplementationID: systemImplementationID,
	}
	if err := tx.Table(newComponent.TableName()).Create(&newComponent).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	labels := make([]riskrel.SystemComponentLabel, 0, len(identityPairs))
	for _, pair := range identityPairs {
		labels = append(labels, riskrel.SystemComponentLabel{
			SystemComponentID: *newComponent.ID,
			Key:               pair.Key,
			Value:             pair.Value,
		})
	}
	if len(labels) > 0 {
		if err := tx.Create(&labels).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	identity := SystemComponentIdentity{
		EntityType:             template.Type,
		IdentityHash:           identityHash,
		SystemImplementationID: systemImplementationID,
		SystemComponentID:      *newComponent.ID,
	}
	insertIdentity := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity)
	if insertIdentity.Error != nil {
		tx.Rollback()
		return nil, insertIdentity.Error
	}
	if insertIdentity.RowsAffected == 0 {
		if err := tx.Delete(&riskrel.SystemComponentLabel{}, "system_component_id = ?", *newComponent.ID).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
		if err := tx.Table(newComponent.TableName()).Delete(&systemComponentRow{}, "id = ?", *newComponent.ID).Error; err != nil {
			tx.Rollback()
			return nil, err
		}

		existingComponentID, err = findSystemComponentIDByIdentityHash(tx, template.Type, identityHash, systemImplementationID)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		if existingComponentID == nil {
			tx.Rollback()
			return nil, errors.New("failed to resolve system component identity")
		}

		existingComponent, fetchErr := fetchSystemComponentByID(tx, *existingComponentID)
		if fetchErr != nil {
			tx.Rollback()
			return nil, fetchErr
		}
		if err := tx.Commit().Error; err != nil {
			return nil, err
		}
		return existingComponent.toSystemComponent(), nil
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return newComponent.toSystemComponent(), nil
}

func (row assessmentSubjectRow) toAssessmentSubject() *relational.AssessmentSubject {
	return &relational.AssessmentSubject{
		UUIDModel:   row.UUIDModel,
		SSPID:       row.SSPID,
		Type:        row.Type,
		Description: row.Description,
		Remarks:     row.Remarks,
		Props:       row.Props,
		Links:       row.Links,
	}
}

func (row systemComponentRow) toSystemComponent() *relational.SystemComponent {
	return &relational.SystemComponent{
		UUIDModel:              row.UUIDModel,
		Type:                   row.Type,
		Title:                  row.Title,
		Description:            row.Description,
		Purpose:                row.Purpose,
		Remarks:                row.Remarks,
		Props:                  row.Props,
		Links:                  row.Links,
		SystemImplementationId: row.SystemImplementationID,
	}
}

func findAssessmentSubjectIDByIdentityHash(tx *gorm.DB, subjectType, identityHash string) (*uuid.UUID, error) {
	var identity AssessmentSubjectIdentity
	if err := tx.Where("entity_type = ? AND identity_hash = ?", subjectType, identityHash).First(&identity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &identity.AssessmentSubjectID, nil
}

func findSystemComponentIDByIdentityHash(tx *gorm.DB, templateType, identityHash string, systemImplementationID uuid.UUID) (*uuid.UUID, error) {
	var identity SystemComponentIdentity
	if err := tx.Where(
		"entity_type = ? AND identity_hash = ? AND system_implementation_id = ?",
		templateType,
		identityHash,
		systemImplementationID,
	).First(&identity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &identity.SystemComponentID, nil
}

func findAssessmentSubjectIDByLabelSet(tx *gorm.DB, subjectType string, labels []identityLabelPair) (*uuid.UUID, error) {
	if len(labels) == 0 {
		return nil, nil
	}

	identityKeys := make([]string, 0, len(labels))
	for _, label := range labels {
		identityKeys = append(identityKeys, label.Key)
	}

	query := tx.Table("assessment_subject_labels AS asl").
		Select("asl.assessment_subject_id").
		Joins("JOIN assessment_subjects AS s ON s.id = asl.assessment_subject_id").
		Where("asl.key IN ?", identityKeys).
		Where("s.type = ?", subjectType).
		Group("asl.assessment_subject_id").
		Having("COUNT(*) = ?", len(labels))

	for _, label := range labels {
		query = query.Having(
			"SUM(CASE WHEN asl.key = ? AND asl.value = ? THEN 1 ELSE 0 END) = 1",
			label.Key,
			label.Value,
		)
	}

	var ids []uuid.UUID
	if err := query.Order("asl.assessment_subject_id ASC").Limit(1).Pluck("asl.assessment_subject_id", &ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	return &ids[0], nil
}

func findSystemComponentIDByLabelSet(tx *gorm.DB, templateType string, labels []identityLabelPair, systemImplementationID uuid.UUID) (*uuid.UUID, error) {
	if len(labels) == 0 {
		return nil, nil
	}

	identityKeys := make([]string, 0, len(labels))
	for _, label := range labels {
		identityKeys = append(identityKeys, label.Key)
	}

	query := tx.Table("system_component_labels AS scl").
		Select("scl.system_component_id").
		Joins("JOIN system_components AS sc ON sc.id = scl.system_component_id").
		Where("scl.key IN ?", identityKeys).
		Where("sc.type = ?", templateType).
		Where("sc.system_implementation_id = ?", systemImplementationID).
		Group("scl.system_component_id").
		Having("COUNT(*) = ?", len(labels))

	for _, label := range labels {
		query = query.Having(
			"SUM(CASE WHEN scl.key = ? AND scl.value = ? THEN 1 ELSE 0 END) = 1",
			label.Key,
			label.Value,
		)
	}

	var ids []uuid.UUID
	if err := query.Order("scl.system_component_id ASC").Limit(1).Pluck("scl.system_component_id", &ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	return &ids[0], nil
}

func deleteStaleAssessmentSubjectIdentity(tx *gorm.DB, entityType, identityHash string, assessmentSubjectID uuid.UUID) error {
	return tx.
		Where(
			"entity_type = ? AND identity_hash = ? AND assessment_subject_id = ?",
			entityType,
			identityHash,
			assessmentSubjectID,
		).
		Delete(&AssessmentSubjectIdentity{}).Error
}

func deleteStaleSystemComponentIdentity(tx *gorm.DB, entityType, identityHash string, systemImplementationID uuid.UUID) error {
	return tx.
		Where(
			"entity_type = ? AND identity_hash = ? AND system_implementation_id = ?",
			entityType,
			identityHash,
			systemImplementationID,
		).
		Delete(&SystemComponentIdentity{}).Error
}

func buildEntityIdentityHash(entityType string, labels []identityLabelPair) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(entityType))
	_, _ = hash.Write([]byte("|"))
	for _, label := range labels {
		_, _ = hash.Write([]byte(label.Key))
		_, _ = hash.Write([]byte("="))
		_, _ = hash.Write([]byte(label.Value))
		_, _ = hash.Write([]byte("|"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func fetchAssessmentSubjectByID(tx *gorm.DB, id uuid.UUID) (*assessmentSubjectRow, error) {
	var row assessmentSubjectRow
	if err := tx.Table(row.TableName()).First(&row, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func fetchSystemComponentByID(tx *gorm.DB, id uuid.UUID) (*systemComponentRow, error) {
	var row systemComponentRow
	if err := tx.Table(row.TableName()).First(&row, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

type systemImplementationIDRow struct {
	ID                   uuid.UUID `gorm:"column:id;type:uuid;primaryKey"`
	SystemSecurityPlanID uuid.UUID `gorm:"column:system_security_plan_id;type:uuid"`
}

func (systemImplementationIDRow) TableName() string {
	return "system_implementations"
}

func findSystemImplementationIDBySystemSecurityPlanID(tx *gorm.DB, systemSecurityPlanID uuid.UUID) (uuid.UUID, error) {
	var row systemImplementationIDRow
	if err := tx.Table(row.TableName()).
		Select("id", "system_security_plan_id").
		Where("system_security_plan_id = ?", systemSecurityPlanID).
		First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return uuid.Nil, newValidationError("systemSecurityPlanId was not found")
		}
		return uuid.Nil, err
	}
	return row.ID, nil
}

func projectIdentityLabelPairs(identityKeys []string, evidenceLabels []relational.Labels) ([]identityLabelPair, error) {
	labelsByKey, err := buildEvidenceLabelMap(evidenceLabels)
	if err != nil {
		return nil, err
	}

	pairs := make([]identityLabelPair, 0, len(identityKeys))
	for _, key := range identityKeys {
		value, exists := labelsByKey[key]
		if !exists || strings.TrimSpace(value) == "" {
			return nil, newValidationError(fmt.Sprintf("identity label key %q was not found in evidence labels", key))
		}
		pairs = append(pairs, identityLabelPair{Key: key, Value: value})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Key == pairs[j].Key {
			return pairs[i].Value < pairs[j].Value
		}
		return pairs[i].Key < pairs[j].Key
	})

	return pairs, nil
}

func buildEvidenceLabelMap(evidenceLabels []relational.Labels) (map[string]string, error) {
	labelsByKey := make(map[string]string, len(evidenceLabels))
	for _, label := range evidenceLabels {
		key := strings.ToLower(strings.TrimSpace(label.Name))
		value := strings.TrimSpace(label.Value)
		if key == "" {
			continue
		}
		if existingValue, exists := labelsByKey[key]; exists && existingValue != value {
			return nil, newValidationError(fmt.Sprintf("evidence labels contain conflicting values for key %q", key))
		}
		labelsByKey[key] = value
	}
	return labelsByKey, nil
}

func matchesSubjectTemplateSelectorLabels(selectors []SubjectTemplateSelectorLabel, labelsByKey map[string]string) bool {
	if len(selectors) == 0 {
		return false
	}
	for _, selector := range selectors {
		value, ok := labelsByKey[selector.Key]
		if !ok || value != selector.Value {
			return false
		}
	}
	return true
}

func hasAllIdentityLabelKeys(identityKeys []string, labelsByKey map[string]string) bool {
	for _, key := range identityKeys {
		value, ok := labelsByKey[key]
		if !ok || strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func replaceSubjectTemplateSelectorLabels(tx *gorm.DB, subjectTemplateID uuid.UUID, labels []SubjectTemplateSelectorLabelInput) error {
	if err := tx.Delete(&SubjectTemplateSelectorLabel{}, "subject_template_id = ?", subjectTemplateID).Error; err != nil {
		return err
	}

	rows := make([]SubjectTemplateSelectorLabel, 0, len(labels))
	for _, label := range labels {
		rows = append(rows, SubjectTemplateSelectorLabel{
			SubjectTemplateID: subjectTemplateID,
			Key:               label.Key,
			Value:             label.Value,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return tx.Create(&rows).Error
}

func replaceSubjectTemplateLabelSchema(tx *gorm.DB, subjectTemplateID uuid.UUID, fields []SubjectTemplateLabelSchemaFieldInput) error {
	if err := tx.Delete(&SubjectTemplateLabelSchemaField{}, "subject_template_id = ?", subjectTemplateID).Error; err != nil {
		return err
	}

	rows := make([]SubjectTemplateLabelSchemaField, 0, len(fields))
	for _, field := range fields {
		rows = append(rows, SubjectTemplateLabelSchemaField{
			SubjectTemplateID: subjectTemplateID,
			Key:               field.Key,
			Description:       field.Description,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return tx.Create(&rows).Error
}

func validateSubjectTemplatePayload(payload *SubjectTemplatePayload) error {
	if payload == nil {
		return newValidationError("payload is required")
	}

	normalizeSubjectTemplatePayload(payload)

	if err := validateSubjectTemplateRequiredText("name", payload.Name); err != nil {
		return err
	}
	if err := validateSubjectTemplateRequiredText("type", payload.Type); err != nil {
		return err
	}
	if !IsValidSubjectTemplateType(payload.Type) {
		return newValidationError("invalid type")
	}
	if err := validateSubjectTemplateRequiredText("sourceMode", payload.SourceMode); err != nil {
		return err
	}
	if !IsValidSubjectTemplateSourceMode(payload.SourceMode) {
		return newValidationError("invalid sourceMode")
	}

	if err := validateSubjectTemplateIdentityLabelKeys(payload.IdentityLabelKeys); err != nil {
		return err
	}
	if err := validateSubjectTemplateSelectorLabels(payload.SelectorLabels); err != nil {
		return err
	}
	labelSchemaKeys, err := validateSubjectTemplateLabelSchema(payload.LabelSchema)
	if err != nil {
		return err
	}

	for _, key := range payload.IdentityLabelKeys {
		if _, exists := labelSchemaKeys[key]; !exists {
			return newValidationError(fmt.Sprintf("identityLabelKeys key %q must exist in labelSchema", key))
		}
	}

	return nil
}

func validateSubjectTemplateIdentityLabelKeys(keys []string) error {
	if err := validateMaxItems("identityLabelKeys", len(keys), maxSubjectTemplateIdentityKeys); err != nil {
		return err
	}
	if len(keys) == 0 {
		return newValidationError("identityLabelKeys is required")
	}

	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if err := validateSubjectTemplateRequiredText("identityLabelKeys", key); err != nil {
			return err
		}
		if _, exists := seen[key]; exists {
			return newValidationError("identityLabelKeys contains duplicate keys")
		}
		seen[key] = struct{}{}
	}

	return nil
}

func validateSubjectTemplateSelectorLabels(labels []SubjectTemplateSelectorLabelInput) error {
	if err := validateMaxItems("selectorLabels", len(labels), maxSubjectTemplateSelectorLabels); err != nil {
		return err
	}
	if len(labels) == 0 {
		return newValidationError("selectorLabels is required")
	}

	seen := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if err := validateSubjectTemplateRequiredText("selectorLabels.key", label.Key); err != nil {
			return err
		}
		if err := validateSubjectTemplateRequiredText("selectorLabels.value", label.Value); err != nil {
			return err
		}
		if _, exists := seen[label.Key]; exists {
			return newValidationError("selectorLabels contains duplicate keys")
		}
		seen[label.Key] = struct{}{}
	}

	return nil
}

func validateSubjectTemplateLabelSchema(fields []SubjectTemplateLabelSchemaFieldInput) (map[string]struct{}, error) {
	if err := validateMaxItems("labelSchema", len(fields), maxSubjectTemplateLabelSchemaItems); err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, newValidationError("labelSchema is required")
	}

	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if err := validateSubjectTemplateRequiredText("labelSchema.key", field.Key); err != nil {
			return nil, err
		}
		if err := validateSubjectTemplateOptionalText("labelSchema.description", field.Description); err != nil {
			return nil, err
		}
		if _, exists := seen[field.Key]; exists {
			return nil, newValidationError("labelSchema contains duplicate keys")
		}
		seen[field.Key] = struct{}{}
	}

	return seen, nil
}

func validateResolveOrUpsertAssessmentSubjectInput(input ResolveOrUpsertAssessmentSubjectInput) error {
	return validateResolveOrUpsertInput(input.SubjectTemplateID, input.EvidenceLabels)
}

func validateResolveOrUpsertSystemComponentInput(input ResolveOrUpsertSystemComponentInput) error {
	if input.SystemSecurityPlanID == uuid.Nil {
		return newValidationError("systemSecurityPlanId is required")
	}
	return validateResolveOrUpsertInput(input.SubjectTemplateID, input.EvidenceLabels)
}

func validateResolveOrUpsertInput(subjectTemplateID uuid.UUID, evidenceLabels []relational.Labels) error {
	if subjectTemplateID == uuid.Nil {
		return newValidationError("subjectTemplateId is required")
	}
	if len(evidenceLabels) == 0 {
		return newValidationError("evidenceLabels is required")
	}
	return nil
}

func normalizeSubjectTemplatePayload(payload *SubjectTemplatePayload) {
	payload.Name = strings.TrimSpace(payload.Name)
	payload.Type = NormalizeSubjectTemplateType(payload.Type)
	payload.SourceMode = NormalizeSubjectTemplateSourceMode(payload.SourceMode)

	for i := range payload.IdentityLabelKeys {
		payload.IdentityLabelKeys[i] = strings.ToLower(strings.TrimSpace(payload.IdentityLabelKeys[i]))
	}
	sort.Strings(payload.IdentityLabelKeys)

	for i := range payload.SelectorLabels {
		payload.SelectorLabels[i].Key = strings.ToLower(strings.TrimSpace(payload.SelectorLabels[i].Key))
		payload.SelectorLabels[i].Value = strings.TrimSpace(payload.SelectorLabels[i].Value)
	}

	for i := range payload.LabelSchema {
		payload.LabelSchema[i].Key = strings.ToLower(strings.TrimSpace(payload.LabelSchema[i].Key))
		if payload.LabelSchema[i].Description != nil {
			normalizedDescription := strings.TrimSpace(*payload.LabelSchema[i].Description)
			payload.LabelSchema[i].Description = &normalizedDescription
		}
	}
}

func validateSubjectTemplateRequiredText(field, value string) error {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return newValidationError(fmt.Sprintf("%s is required", field))
	}
	return validateSubjectTemplateTextLength(field, normalized)
}

func validateSubjectTemplateOptionalText(field string, value *string) error {
	if value == nil {
		return nil
	}
	normalized := strings.TrimSpace(*value)
	*value = normalized
	return validateSubjectTemplateTextLength(field, normalized)
}

func validateSubjectTemplateTextLength(field, value string) error {
	if utf8.RuneCountInString(value) > maxSubjectTemplateFieldLength {
		return newValidationError(fmt.Sprintf("%s must be at most %d characters", field, maxSubjectTemplateFieldLength))
	}
	return nil
}

func fetchSubjectTemplateByID(db *gorm.DB, id uuid.UUID) (*SubjectTemplate, error) {
	var row SubjectTemplate
	if err := db.
		Preload("SelectorLabels", preloadSubjectTemplateSelectorLabels).
		Preload("LabelSchema", preloadSubjectTemplateLabelSchema).
		First(&row, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func preloadSubjectTemplateSelectorLabels(db *gorm.DB) *gorm.DB {
	return db.Order("key ASC")
}

func preloadSubjectTemplateLabelSchema(db *gorm.DB) *gorm.DB {
	return db.Order("key ASC")
}
