package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
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
	Name                string
	Type                string
	TitleTemplate       *string
	DescriptionTemplate *string
	PurposeTemplate     *string
	RemarksTemplate     *string
	IdentityLabelKeys   []string
	Props               []relational.Prop
	Links               []relational.Link
	SourceMode          string
	SelectorLabels      []SubjectTemplateSelectorLabelInput
	LabelSchema         []SubjectTemplateLabelSchemaFieldInput
}

type ResolveOrUpsertAssessmentSubjectInput struct {
	SubjectTemplateID uuid.UUID
	EvidenceLabels    []relational.Labels
}

type ResolveOrUpsertSystemComponentInput struct {
	SubjectTemplateID    uuid.UUID
	SystemSecurityPlanID uuid.UUID
	EvidenceLabels       []relational.Labels
}

type ResolveOrUpsertSystemComponentsForEvidenceInput struct {
	SystemSecurityPlanID uuid.UUID
	EvidenceLabels       []relational.Labels
}

type ResolveOrUpsertComponentDefinitionInput struct {
	EvidenceLabels []relational.Labels
}

type ResolveOrUpsertComponentDefinitionResult struct {
	DefinedComponentIDs []uuid.UUID
}

type identityLabelPair struct {
	Key   string
	Value string
}

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
		Name:                payload.Name,
		Type:                payload.Type,
		TitleTemplate:       payload.TitleTemplate,
		DescriptionTemplate: payload.DescriptionTemplate,
		PurposeTemplate:     payload.PurposeTemplate,
		RemarksTemplate:     payload.RemarksTemplate,
		IdentityLabelKeys:   datatypes.NewJSONSlice(payload.IdentityLabelKeys),
		Props:               datatypes.NewJSONSlice(payload.Props),
		Links:               datatypes.NewJSONSlice(payload.Links),
		SourceMode:          payload.SourceMode,
	}

	if err := tx.Select(
		"ID",
		"CreatedAt",
		"UpdatedAt",
		"Name",
		"Type",
		"TitleTemplate",
		"DescriptionTemplate",
		"PurposeTemplate",
		"RemarksTemplate",
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
	existing.TitleTemplate = payload.TitleTemplate
	existing.DescriptionTemplate = payload.DescriptionTemplate
	existing.PurposeTemplate = payload.PurposeTemplate
	existing.RemarksTemplate = payload.RemarksTemplate
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

// TODO[codex-review]: Dead code. Consider removing. For Copilot - this is a known issue and the moment the code will be removed is afterwards a full integration test battery. Please ignore review comments related to these methods / this comment
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

// TODO[codex-review]: Dead code. Consider removing. For Copilot - this is a known issue and the moment the code will be removed is afterwards a full integration test battery. Please ignore review comments related to these methods / this comment
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

// TODO[codex-review]: Dead code. Consider removing. For Copilot - this is a known issue and the moment the code will be removed is afterwards a full integration test battery. Please ignore review comments related to these methods / this comment
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
				if err := deleteStaleSystemComponentLabels(tx, *existingComponentID); err != nil {
					tx.Rollback()
					return nil, err
				}
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

// componentDefinitionNamespace is a fixed v4 UUID used as a namespace for
// deterministic (v5-style) ComponentDefinition IDs seeded from identity hashes.
var componentDefinitionNamespace = uuid.MustParse("a4e3c2d1-b0f9-4e8a-9c7d-6f5e4d3c2b1a")

func (s *SubjectTemplateService) ResolveOrUpsertComponentDefinition(input ResolveOrUpsertComponentDefinitionInput) (*ResolveOrUpsertComponentDefinitionResult, error) {
	if len(input.EvidenceLabels) == 0 {
		return &ResolveOrUpsertComponentDefinitionResult{}, nil
	}

	labelsByKey, err := buildEvidenceLabelMap(input.EvidenceLabels)
	if err != nil {
		return nil, err
	}

	// Pre-filter: extract _plugin value for efficient template lookup.
	pluginValue, hasPlugin := labelsByKey["_plugin"]
	if !hasPlugin || strings.TrimSpace(pluginValue) == "" {
		return &ResolveOrUpsertComponentDefinitionResult{}, nil
	}

	var templates []SubjectTemplate
	if err := s.db.
		Where("type = ? AND source_mode = ?", subjectTemplateTypeComponent, subjectTemplateSourceModeRuntimeDerived).
		Joins("JOIN subject_template_selector_labels ON subject_template_selector_labels.subject_template_id = subject_templates.id AND subject_template_selector_labels.key = ? AND subject_template_selector_labels.value = ?", "_plugin", pluginValue).
		Preload("SelectorLabels", preloadSubjectTemplateSelectorLabels).
		Preload("LabelSchema", preloadSubjectTemplateLabelSchema).
		Order("created_at asc").
		Limit(maxRuntimeComponentTemplatesScan + 1).
		Find(&templates).Error; err != nil {
		return nil, err
	}
	if len(templates) > maxRuntimeComponentTemplatesScan {
		return nil, fmt.Errorf(
			"resolve component definitions reached scan limit of %d runtime-derived component subject templates",
			maxRuntimeComponentTemplatesScan,
		)
	}

	result := &ResolveOrUpsertComponentDefinitionResult{}
	seen := make(map[uuid.UUID]struct{})

	for _, template := range templates {
		if !matchesSubjectTemplateSelectorLabels(template.SelectorLabels, labelsByKey) {
			continue
		}
		if !hasAllIdentityLabelKeys(template.IdentityLabelKeys, labelsByKey) {
			continue
		}

		identityPairs, err := projectIdentityLabelPairs(template.IdentityLabelKeys, input.EvidenceLabels)
		if err != nil {
			return nil, err
		}
		// Build schema label keys leniently: include only those keys that are present
		// in the evidence labels. Unlike identity labels, schema labels may be optional
		// (e.g., contextual labels like "env"), so missing keys should not cause an error.
		schemaLabelKeys := []string{}
		for _, label := range template.LabelSchema {
			if _, ok := labelsByKey[label.Key]; ok {
				schemaLabelKeys = append(schemaLabelKeys, label.Key)
			}
		}
		schemaLabelPairs, err := projectIdentityLabelPairs(schemaLabelKeys, input.EvidenceLabels)
		if err != nil {
			return nil, err
		}

		identityHash := buildEntityIdentityHash(template.Type, identityPairs)

		definedComponentID, err := s.resolveOrCreateComponentDefinition(template, pluginValue, identityPairs, schemaLabelPairs, identityHash)
		if err != nil {
			return nil, err
		}
		if definedComponentID == nil {
			continue
		}
		if _, exists := seen[*definedComponentID]; exists {
			continue
		}
		seen[*definedComponentID] = struct{}{}
		result.DefinedComponentIDs = append(result.DefinedComponentIDs, *definedComponentID)
	}

	return result, nil
}

func (s *SubjectTemplateService) resolveOrCreateComponentDefinition(template SubjectTemplate, pluginValue string, identityPairs []identityLabelPair, schemaLabels []identityLabelPair, identityHash string) (*uuid.UUID, error) {
	// Check if identity already exists.
	var existingIdentity ComponentDefinitionIdentity
	if err := s.db.Where("entity_type = ? AND identity_hash = ?", subjectTemplateTypeComponent, identityHash).First(&existingIdentity).Error; err == nil {
		return &existingIdentity.DefinedComponentID, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// Build label map for template rendering
	labelMap := make(map[string]string)
	for _, pair := range schemaLabels {
		labelMap[pair.Key] = pair.Value
	}

	// Render template fields
	title := template.Name
	if template.TitleTemplate != nil {
		rendered, err := renderTemplate(*template.TitleTemplate, labelMap)
		if err != nil {
			return nil, fmt.Errorf("failed to render title template: %w", err)
		}
		if rendered != "" {
			title = rendered
		}
	}

	description := ""
	if template.DescriptionTemplate != nil {
		rendered, err := renderTemplate(*template.DescriptionTemplate, labelMap)
		if err != nil {
			return nil, fmt.Errorf("failed to render description template: %w", err)
		}
		description = rendered
	}

	purpose := ""
	if template.PurposeTemplate != nil {
		rendered, err := renderTemplate(*template.PurposeTemplate, labelMap)
		if err != nil {
			return nil, fmt.Errorf("failed to render purpose template: %w", err)
		}
		purpose = rendered
	}

	remarks := ""
	if template.RemarksTemplate != nil {
		rendered, err := renderTemplate(*template.RemarksTemplate, labelMap)
		if err != nil {
			return nil, fmt.Errorf("failed to render remarks template: %w", err)
		}
		remarks = rendered
	}

	// Generate deterministic IDs:
	// - ComponentDefinition groups by plugin
	// - DefinedComponent is still identity-specific
	normalizedPlugin := strings.ToLower(strings.TrimSpace(pluginValue))
	cdID := uuid.NewSHA1(componentDefinitionNamespace, []byte("plugin:"+normalizedPlugin))
	dcID := uuid.NewSHA1(cdID, []byte(identityHash))
	now := time.Now().UTC()
	componentDefinitionTitle := template.Name
	if normalizedPlugin != "" {
		componentDefinitionTitle = fmt.Sprintf("%s components", normalizedPlugin)
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer rollbackTxOnPanic(tx)

	// Upsert ComponentDefinition.
	cd := relational.ComponentDefinition{
		UUIDModel: relational.UUIDModel{ID: &cdID},
	}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Omit(clause.Associations).Create(&cd).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// Upsert metadata separately so repeated calls do not create duplicate polymorphic metadata rows.
	parentID := cdID.String()
	parentType := "component_definitions"

	// Serialize metadata upsert per ComponentDefinition to avoid duplicate metadata rows
	// when concurrent requests resolve the same plugin-scoped ComponentDefinition.
	var lockedCD relational.ComponentDefinition
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&lockedCD, "id = ?", cdID).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	var existingMetadata relational.Metadata
	metadataQuery := tx.Model(&relational.Metadata{}).Where("parent_id = ? AND parent_type = ?", parentID, parentType)
	if err := metadataQuery.First(&existingMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			md := relational.Metadata{
				Title:        componentDefinitionTitle,
				Version:      "1.0.0",
				OscalVersion: versioning.GetLatestSupportedVersion(),
				LastModified: &now,
				ParentID:     &parentID,
				ParentType:   &parentType,
			}
			if err := tx.Omit(clause.Associations).Create(&md).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		} else {
			tx.Rollback()
			return nil, err
		}
	} else {
		if err := tx.Model(&relational.Metadata{}).Where("parent_id = ? AND parent_type = ?", parentID, parentType).Updates(map[string]interface{}{
			"title":         componentDefinitionTitle,
			"version":       "1.0.0",
			"oscal_version": versioning.GetLatestSupportedVersion(),
			"last_modified": &now,
		}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// Upsert DefinedComponent with rendered template values.
	dc := relational.DefinedComponent{
		UUIDModel:             relational.UUIDModel{ID: &dcID},
		Type:                  template.Type,
		Title:                 title,
		Description:           description,
		Purpose:               purpose,
		Remarks:               remarks,
		ComponentDefinitionID: &cdID,
	}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Omit(clause.Associations).Create(&dc).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// Upsert labels.
	labels := make([]riskrel.ComponentDefinitionLabel, 0, len(identityPairs))
	for _, pair := range identityPairs {
		labels = append(labels, riskrel.ComponentDefinitionLabel{
			DefinedComponentID:    dcID,
			ComponentDefinitionID: cdID,
			Key:                   pair.Key,
			Value:                 pair.Value,
		})
	}
	if len(labels) > 0 {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&labels).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// Upsert identity record.
	identity := ComponentDefinitionIdentity{
		EntityType:            subjectTemplateTypeComponent,
		IdentityHash:          identityHash,
		ComponentDefinitionID: cdID,
		DefinedComponentID:    dcID,
	}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &dcID, nil
}

func (s *SubjectTemplateService) FindSystemComponentsByDefinedComponentIDs(definedComponentIDs []uuid.UUID) ([]relational.SystemComponent, error) {
	if len(definedComponentIDs) == 0 {
		return nil, nil
	}

	var components []relational.SystemComponent
	if err := s.db.Where("defined_component_id IN ?", definedComponentIDs).Find(&components).Error; err != nil {
		return nil, err
	}
	return components, nil
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

func deleteStaleSystemComponentLabels(tx *gorm.DB, systemComponentID uuid.UUID) error {
	return tx.
		Where("system_component_id = ?", systemComponentID).
		Delete(&riskrel.SystemComponentLabel{}).Error
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

	// Validate template fields against label schema
	labelSchemaFields := make([]SubjectTemplateLabelSchemaField, 0, len(payload.LabelSchema))
	for _, field := range payload.LabelSchema {
		labelSchemaFields = append(labelSchemaFields, SubjectTemplateLabelSchemaField{
			Key:         field.Key,
			Description: field.Description,
		})
	}
	if err := validateSubjectTemplateOptionalText("titleTemplate", payload.TitleTemplate); err != nil {
		return newValidationError(err.Error())
	}
	if err := validateSubjectTemplateOptionalText("descriptionTemplate", payload.DescriptionTemplate); err != nil {
		return newValidationError(err.Error())
	}
	if err := validateSubjectTemplateOptionalText("purposeTemplate", payload.PurposeTemplate); err != nil {
		return newValidationError(err.Error())
	}
	if err := validateSubjectTemplateOptionalText("remarksTemplate", payload.RemarksTemplate); err != nil {
		return newValidationError(err.Error())
	}

	if err := validateTemplateAgainstSchema(payload.TitleTemplate, labelSchemaFields); err != nil {
		return newValidationError(fmt.Sprintf("titleTemplate validation failed: %v", err))
	}
	if err := validateTemplateAgainstSchema(payload.DescriptionTemplate, labelSchemaFields); err != nil {
		return newValidationError(fmt.Sprintf("descriptionTemplate validation failed: %v", err))
	}
	if err := validateTemplateAgainstSchema(payload.PurposeTemplate, labelSchemaFields); err != nil {
		return newValidationError(fmt.Sprintf("purposeTemplate validation failed: %v", err))
	}
	if err := validateTemplateAgainstSchema(payload.RemarksTemplate, labelSchemaFields); err != nil {
		return newValidationError(fmt.Sprintf("remarksTemplate validation failed: %v", err))
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

// pluginSelectorLabelKey is the selector-label key used to associate a subject template with
// a specific plugin. Agents must set this label when registering subject templates.
const pluginSelectorLabelKey = "_plugin"

// BatchSubjectTemplateItem is a single item in a batch upsert request.
// The plugin_id is inherited from the batch-level scope (via selector-label) and each item is
// expected to carry a selector-label with key=pluginSelectorLabelKey and value=pluginID.
// ID is mandatory and must be provided by the caller (agent-side UUID generation).
// TODO: agents should use deterministic/generational UUID derivation so that re-running a batch
// produces the same IDs for the same logical templates. The derivation strategy (e.g.
// sha1(plugin_id + name + type)) must be decided and implemented on the agent side.
type BatchSubjectTemplateItem struct {
	ID                  uuid.UUID
	Name                string
	Type                string
	TitleTemplate       *string
	DescriptionTemplate *string
	PurposeTemplate     *string
	RemarksTemplate     *string
	IdentityLabelKeys   []string
	Props               []relational.Prop
	Links               []relational.Link
	SourceMode          string
	SelectorLabels      []SubjectTemplateSelectorLabelInput
	LabelSchema         []SubjectTemplateLabelSchemaFieldInput
}

// BatchUpsertSubjectTemplatesResult is the result of a SubjectTemplateService.BatchUpsert call.
type BatchUpsertSubjectTemplatesResult struct {
	Created   []SubjectTemplate
	Updated   []SubjectTemplate
	Deleted   []uuid.UUID
	Unchanged []uuid.UUID
}

// BatchUpsert reconciles the full set of subject templates scoped to a given pluginID.
// Scope is determined by templates that carry a selector-label with
// key=pluginSelectorLabelKey ("_plugin") and value=pluginID.
// All mutations are executed in a single atomic transaction.
// Templates not present in the payload are always deleted (no in-use guard).
func (s *SubjectTemplateService) BatchUpsert(pluginID string, items []BatchSubjectTemplateItem) (*BatchUpsertSubjectTemplatesResult, error) {
	pluginID = strings.TrimSpace(pluginID)
	if err := validateSubjectTemplateRequiredText("pluginId", pluginID); err != nil {
		return nil, err
	}

	// Validate that all items carry a non-zero, unique ID supplied by the caller.
	type resolvedItem struct {
		id   uuid.UUID
		item BatchSubjectTemplateItem
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

	// Normalize and validate all payloads before opening the transaction.
	for i, r := range resolved {
		payload := batchSubjectItemToPayload(r.item)
		if err := validateSubjectTemplatePayload(&payload); err != nil {
			return nil, fmt.Errorf("item %d (id %s): %w", i, r.id, err)
		}
		resolved[i].item = batchSubjectItemFromPayload(r.item, payload)
	}

	// Validate the plugin scoping selector label on normalized items.
	for i, r := range resolved {
		hasPluginLabel := false
		for _, sl := range r.item.SelectorLabels {
			if sl.Key == pluginSelectorLabelKey && sl.Value == pluginID {
				hasPluginLabel = true
				break
			}
		}
		if !hasPluginLabel {
			return nil, newValidationError(fmt.Sprintf("item %d (id %s): missing selector label %s=%s", i, r.id, pluginSelectorLabelKey, pluginID))
		}
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
	existingRows, err := listSubjectTemplatesByPluginSelectorLabel(tx, pluginID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	existingByID := make(map[uuid.UUID]SubjectTemplate, len(existingRows))
	for _, row := range existingRows {
		existingByID[*row.ID] = row
	}

	result := &BatchUpsertSubjectTemplatesResult{
		Created:   make([]SubjectTemplate, 0),
		Updated:   make([]SubjectTemplate, 0),
		Deleted:   make([]uuid.UUID, 0),
		Unchanged: make([]uuid.UUID, 0),
	}

	// Collect IDs that need to be created (not already in this scope), then check
	// for cross-scope collisions with a single query instead of one COUNT per item.
	newIDs := make([]uuid.UUID, 0, len(resolved))
	for _, r := range resolved {
		if _, exists := existingByID[r.id]; !exists {
			newIDs = append(newIDs, r.id)
		}
	}
	if len(newIDs) > 0 {
		var collidingIDs []uuid.UUID
		if err := tx.Model(&SubjectTemplate{}).Where("id IN ?", newIDs).Pluck("id", &collidingIDs).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
		if len(collidingIDs) > 0 {
			tx.Rollback()
			return nil, newValidationError(fmt.Sprintf("id %s already exists in a different scope", collidingIDs[0]))
		}
	}

	// Create or update.
	for _, r := range resolved {
		payload := batchSubjectItemToPayload(r.item)
		if existing, exists := existingByID[r.id]; exists {
			if subjectTemplateMatchesPayload(existing, payload) {
				result.Unchanged = append(result.Unchanged, r.id)
				continue
			}
			row, err := updateSubjectTemplateInTx(tx, r.id, payload)
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("update subject template %s: %w", r.id, err)
			}
			result.Updated = append(result.Updated, *row)
		} else {
			row, err := createSubjectTemplateInTx(tx, r.id, payload)
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("create subject template %s: %w", r.id, err)
			}
			result.Created = append(result.Created, *row)
		}
	}

	// Delete.
	for id := range existingByID {
		if _, inPayload := payloadIDs[id]; inPayload {
			continue
		}

		if err := tx.Delete(&SubjectTemplateSelectorLabel{}, "subject_template_id = ?", id).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("delete selector labels for subject template %s: %w", id, err)
		}
		if err := tx.Delete(&SubjectTemplateLabelSchemaField{}, "subject_template_id = ?", id).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("delete label schema for subject template %s: %w", id, err)
		}
		if err := tx.Delete(&SubjectTemplate{}, "id = ?", id).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("delete subject template %s: %w", id, err)
		}
		result.Deleted = append(result.Deleted, id)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return result, nil
}

// listSubjectTemplatesByPluginSelectorLabel returns all SubjectTemplates that carry a selector-label
// with key=pluginSelectorLabelKey and value=pluginID.
func listSubjectTemplatesByPluginSelectorLabel(db *gorm.DB, pluginID string) ([]SubjectTemplate, error) {
	var rows []SubjectTemplate
	if err := db.
		Joins("JOIN subject_template_selector_labels sl ON sl.subject_template_id = subject_templates.id").
		Where("sl.key = ? AND sl.value = ?", pluginSelectorLabelKey, pluginID).
		Preload("SelectorLabels", preloadSubjectTemplateSelectorLabels).
		Preload("LabelSchema", preloadSubjectTemplateLabelSchema).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// batchSubjectItemToPayload converts a BatchSubjectTemplateItem into a SubjectTemplatePayload.
func batchSubjectItemToPayload(item BatchSubjectTemplateItem) SubjectTemplatePayload {
	return SubjectTemplatePayload{
		Name:                item.Name,
		Type:                item.Type,
		TitleTemplate:       item.TitleTemplate,
		DescriptionTemplate: item.DescriptionTemplate,
		PurposeTemplate:     item.PurposeTemplate,
		RemarksTemplate:     item.RemarksTemplate,
		IdentityLabelKeys:   append([]string{}, item.IdentityLabelKeys...),
		Props:               append([]relational.Prop{}, item.Props...),
		Links:               append([]relational.Link{}, item.Links...),
		SourceMode:          item.SourceMode,
		SelectorLabels:      append([]SubjectTemplateSelectorLabelInput{}, item.SelectorLabels...),
		LabelSchema:         append([]SubjectTemplateLabelSchemaFieldInput{}, item.LabelSchema...),
	}
}

// batchSubjectItemFromPayload copies normalised payload fields back into the item.
func batchSubjectItemFromPayload(item BatchSubjectTemplateItem, payload SubjectTemplatePayload) BatchSubjectTemplateItem {
	item.Name = payload.Name
	item.Type = payload.Type
	item.TitleTemplate = payload.TitleTemplate
	item.DescriptionTemplate = payload.DescriptionTemplate
	item.PurposeTemplate = payload.PurposeTemplate
	item.RemarksTemplate = payload.RemarksTemplate
	item.IdentityLabelKeys = payload.IdentityLabelKeys
	item.Props = payload.Props
	item.Links = payload.Links
	item.SourceMode = payload.SourceMode
	item.SelectorLabels = payload.SelectorLabels
	item.LabelSchema = payload.LabelSchema
	return item
}

// createSubjectTemplateInTx creates a subject template within an existing transaction with the given id.
func createSubjectTemplateInTx(tx *gorm.DB, id uuid.UUID, payload SubjectTemplatePayload) (*SubjectTemplate, error) {
	row := SubjectTemplate{
		Name:                payload.Name,
		Type:                payload.Type,
		TitleTemplate:       payload.TitleTemplate,
		DescriptionTemplate: payload.DescriptionTemplate,
		PurposeTemplate:     payload.PurposeTemplate,
		RemarksTemplate:     payload.RemarksTemplate,
		IdentityLabelKeys:   datatypes.NewJSONSlice(payload.IdentityLabelKeys),
		Props:               datatypes.NewJSONSlice(payload.Props),
		Links:               datatypes.NewJSONSlice(payload.Links),
		SourceMode:          payload.SourceMode,
	}
	row.ID = &id

	if err := tx.Select(
		"ID",
		"CreatedAt",
		"UpdatedAt",
		"Name",
		"Type",
		"TitleTemplate",
		"DescriptionTemplate",
		"PurposeTemplate",
		"RemarksTemplate",
		"IdentityLabelKeys",
		"Props",
		"Links",
		"SourceMode",
	).Create(&row).Error; err != nil {
		return nil, err
	}

	if err := replaceSubjectTemplateSelectorLabels(tx, id, payload.SelectorLabels); err != nil {
		return nil, err
	}
	if err := replaceSubjectTemplateLabelSchema(tx, id, payload.LabelSchema); err != nil {
		return nil, err
	}

	return fetchSubjectTemplateByID(tx, id)
}

// updateSubjectTemplateInTx updates an existing subject template within an existing transaction.
func updateSubjectTemplateInTx(tx *gorm.DB, id uuid.UUID, payload SubjectTemplatePayload) (*SubjectTemplate, error) {
	var existing SubjectTemplate
	if err := tx.First(&existing, "id = ?", id).Error; err != nil {
		return nil, err
	}

	existing.Name = payload.Name
	existing.Type = payload.Type
	existing.TitleTemplate = payload.TitleTemplate
	existing.DescriptionTemplate = payload.DescriptionTemplate
	existing.PurposeTemplate = payload.PurposeTemplate
	existing.RemarksTemplate = payload.RemarksTemplate
	existing.IdentityLabelKeys = datatypes.NewJSONSlice(payload.IdentityLabelKeys)
	existing.Props = datatypes.NewJSONSlice(payload.Props)
	existing.Links = datatypes.NewJSONSlice(payload.Links)
	existing.SourceMode = payload.SourceMode

	if err := tx.Omit("SelectorLabels", "LabelSchema").Save(&existing).Error; err != nil {
		return nil, err
	}

	if err := replaceSubjectTemplateSelectorLabels(tx, *existing.ID, payload.SelectorLabels); err != nil {
		return nil, err
	}
	if err := replaceSubjectTemplateLabelSchema(tx, *existing.ID, payload.LabelSchema); err != nil {
		return nil, err
	}

	return fetchSubjectTemplateByID(tx, *existing.ID)
}

// subjectTemplateFP is an unexported fingerprint struct used to detect whether a batch
// payload differs from a stored template, avoiding unnecessary UPDATE statements.
type subjectTemplateFP struct {
	Name                string            `json:"n"`
	Type                string            `json:"ty"`
	SourceMode          string            `json:"sm"`
	TitleTemplate       *string           `json:"tt,omitempty"`
	DescriptionTemplate *string           `json:"dt,omitempty"`
	PurposeTemplate     *string           `json:"pt,omitempty"`
	RemarksTemplate     *string           `json:"rt,omitempty"`
	IdentityLabelKeys   []string          `json:"ilk"`
	Props               []relational.Prop `json:"props"`
	Links               []relational.Link `json:"links"`
	SelectorLabels      []stSelectorFP    `json:"sl"`
	LabelSchema         []stSchemaFP      `json:"ls"`
}

type stSelectorFP struct {
	Key   string `json:"k"`
	Value string `json:"v"`
}

type stSchemaFP struct {
	Key         string  `json:"k"`
	Description *string `json:"d,omitempty"`
}

// subjectTemplateMatchesPayload returns true when the stored template already reflects
// every field in the payload, so no UPDATE is necessary.
func subjectTemplateMatchesPayload(existing SubjectTemplate, payload SubjectTemplatePayload) bool {
	a := subjectTemplateFPFromExisting(existing)
	b := subjectTemplateFPFromPayload(payload)
	aj, err1 := json.Marshal(a)
	bj, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(aj) == string(bj)
}

func subjectTemplateFPFromExisting(t SubjectTemplate) subjectTemplateFP {
	keys := make([]string, len(t.IdentityLabelKeys))
	copy(keys, t.IdentityLabelKeys)
	sort.Strings(keys)

	selectors := make([]stSelectorFP, 0, len(t.SelectorLabels))
	for _, s := range t.SelectorLabels {
		selectors = append(selectors, stSelectorFP{Key: s.Key, Value: s.Value})
	}
	sort.Slice(selectors, func(i, j int) bool { return selectors[i].Key < selectors[j].Key })

	schema := make([]stSchemaFP, 0, len(t.LabelSchema))
	for _, f := range t.LabelSchema {
		schema = append(schema, stSchemaFP{Key: f.Key, Description: f.Description})
	}
	sort.Slice(schema, func(i, j int) bool { return schema[i].Key < schema[j].Key })

	return subjectTemplateFP{
		Name:                t.Name,
		Type:                t.Type,
		SourceMode:          t.SourceMode,
		TitleTemplate:       t.TitleTemplate,
		DescriptionTemplate: t.DescriptionTemplate,
		PurposeTemplate:     t.PurposeTemplate,
		RemarksTemplate:     t.RemarksTemplate,
		IdentityLabelKeys:   keys,
		Props:               []relational.Prop(t.Props),
		Links:               []relational.Link(t.Links),
		SelectorLabels:      selectors,
		LabelSchema:         schema,
	}
}

func subjectTemplateFPFromPayload(payload SubjectTemplatePayload) subjectTemplateFP {
	keys := make([]string, len(payload.IdentityLabelKeys))
	copy(keys, payload.IdentityLabelKeys)
	sort.Strings(keys)

	selectors := make([]stSelectorFP, 0, len(payload.SelectorLabels))
	for _, s := range payload.SelectorLabels {
		selectors = append(selectors, stSelectorFP(s))
	}
	sort.Slice(selectors, func(i, j int) bool { return selectors[i].Key < selectors[j].Key })

	schema := make([]stSchemaFP, 0, len(payload.LabelSchema))
	for _, f := range payload.LabelSchema {
		schema = append(schema, stSchemaFP(f))
	}
	sort.Slice(schema, func(i, j int) bool { return schema[i].Key < schema[j].Key })

	props := payload.Props
	if props == nil {
		props = []relational.Prop{}
	}
	links := payload.Links
	if links == nil {
		links = []relational.Link{}
	}

	return subjectTemplateFP{
		Name:                payload.Name,
		Type:                payload.Type,
		SourceMode:          payload.SourceMode,
		TitleTemplate:       payload.TitleTemplate,
		DescriptionTemplate: payload.DescriptionTemplate,
		PurposeTemplate:     payload.PurposeTemplate,
		RemarksTemplate:     payload.RemarksTemplate,
		IdentityLabelKeys:   keys,
		Props:               props,
		Links:               links,
		SelectorLabels:      selectors,
		LabelSchema:         schema,
	}
}
