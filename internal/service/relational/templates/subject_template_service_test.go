package templates

import (
	"fmt"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSubjectTemplateService_CreateListGetUpdate(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	created, err := svc.Create(SubjectTemplatePayload{
		Name:              " Runtime component identity ",
		Type:              " COMPONENT ",
		IdentityLabelKeys: []string{" cluster ", " Asset_ID "},
		Props: []relational.Prop{
			{Name: "scope", Value: "runtime"},
		},
		Links: []relational.Link{
			{Href: "https://example.com/subject-template"},
		},
		SourceMode: " Runtime-Derived ",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: " Plugin ", Value: " github "},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: " asset_id ", Description: strPtr(" Unique asset ID ")},
			{Key: " cluster ", Description: strPtr(" Cluster name ")},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.NotNil(t, created.ID)
	require.Equal(t, "Runtime component identity", created.Name)
	require.Equal(t, "component", created.Type)
	require.Equal(t, "runtime-derived", created.SourceMode)
	require.Equal(t, []string{"asset_id", "cluster"}, []string(created.IdentityLabelKeys))
	require.Len(t, created.SelectorLabels, 1)
	require.Equal(t, "plugin", created.SelectorLabels[0].Key)
	require.Equal(t, "github", created.SelectorLabels[0].Value)
	require.Len(t, created.LabelSchema, 2)

	rows, total, err := svc.List(SubjectTemplateListParams{
		Filters: SubjectTemplateListFilters{Type: strPtr(" COMPONENT "), SourceMode: strPtr(" runtime-derived ")},
		Limit:   10,
		Offset:  0,
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, rows, 1)

	got, err := svc.GetByID(*created.ID)
	require.NoError(t, err)
	require.Equal(t, *created.ID, *got.ID)

	updated, err := svc.Update(*created.ID, SubjectTemplatePayload{
		Name:              " Runtime component identity updated ",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "namespace"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "plugin", Value: "gitlab"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "asset_id", Description: strPtr("Unique asset ID")},
			{Key: "namespace", Description: strPtr("Namespace")},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "Runtime component identity updated", updated.Name)
	require.Equal(t, []string{"asset_id", "namespace"}, []string(updated.IdentityLabelKeys))
	require.Len(t, updated.SelectorLabels, 1)
	require.Equal(t, "gitlab", updated.SelectorLabels[0].Value)
	require.Len(t, updated.LabelSchema, 2)
}

func TestSubjectTemplateService_ResolveOrUpsertAssessmentSubjectIdempotent(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	template, err := svc.Create(SubjectTemplatePayload{
		Name:              "Component subject resolver",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "asset_id", Description: strPtr("Asset")},
			{Key: "cluster", Description: strPtr("Cluster")},
		},
	})
	require.NoError(t, err)

	first, err := svc.ResolveOrUpsertAssessmentSubject(ResolveOrUpsertAssessmentSubjectInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
			{Name: "ignored", Value: "x"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotNil(t, first.ID)
	require.Equal(t, "component", first.Type)

	second, err := svc.ResolveOrUpsertAssessmentSubject(ResolveOrUpsertAssessmentSubjectInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, *first.ID, *second.ID)

	var subjectCount int64
	require.NoError(t, db.Table("assessment_subjects").Count(&subjectCount).Error)
	require.Equal(t, int64(1), subjectCount)

	var labelCount int64
	require.NoError(t, db.Model(&riskrel.AssessmentSubjectLabel{}).Where("assessment_subject_id = ?", *first.ID).Count(&labelCount).Error)
	require.Equal(t, int64(2), labelCount)

	var identityCount int64
	require.NoError(t, db.Model(&AssessmentSubjectIdentity{}).Count(&identityCount).Error)
	require.Equal(t, int64(1), identityCount)
}

func TestSubjectTemplateService_ResolveOrUpsertAssessmentSubjectIgnoresNonIdentityLabels(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	template, err := svc.Create(validSubjectTemplatePayload())
	require.NoError(t, err)

	first, err := svc.ResolveOrUpsertAssessmentSubject(ResolveOrUpsertAssessmentSubjectInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, first.ID)

	require.NoError(t, db.Create(&riskrel.AssessmentSubjectLabel{
		AssessmentSubjectID: *first.ID,
		Key:                 "environment",
		Value:               "production",
	}).Error)

	second, err := svc.ResolveOrUpsertAssessmentSubject(ResolveOrUpsertAssessmentSubjectInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, *first.ID, *second.ID)

	var identityCount int64
	require.NoError(t, db.Model(&AssessmentSubjectIdentity{}).Count(&identityCount).Error)
	require.Equal(t, int64(1), identityCount)
}

func TestSubjectTemplateService_ResolveOrUpsertSystemComponentIdempotent(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)
	systemSecurityPlanID := createTestSystemSecurityPlanAndImplementation(t, db)

	template, err := svc.Create(validSubjectTemplatePayload())
	require.NoError(t, err)

	first, err := svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID:    *template.ID,
		SystemSecurityPlanID: systemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotNil(t, first.ID)
	require.Equal(t, "component", first.Type)

	second, err := svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID:    *template.ID,
		SystemSecurityPlanID: systemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
			{Name: "ignored", Value: "x"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, *first.ID, *second.ID)

	var componentCount int64
	require.NoError(t, db.Table("system_components").Count(&componentCount).Error)
	require.Equal(t, int64(1), componentCount)

	var labelCount int64
	require.NoError(t, db.Model(&riskrel.SystemComponentLabel{}).Where("system_component_id = ?", *first.ID).Count(&labelCount).Error)
	require.Equal(t, int64(2), labelCount)

	var identityCount int64
	require.NoError(t, db.Model(&SystemComponentIdentity{}).Count(&identityCount).Error)
	require.Equal(t, int64(1), identityCount)
}

func TestSubjectTemplateService_ResolveOrUpsertSystemComponentsForEvidenceMatchesSelectors(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)
	systemSecurityPlanID := createTestSystemSecurityPlanAndImplementation(t, db)

	_, err := svc.Create(SubjectTemplatePayload{
		Name:              "GitHub Runtime Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	_, err = svc.Create(SubjectTemplatePayload{
		Name:              "GitLab Runtime Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "plugin", Value: "gitlab"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	_, err = svc.Create(SubjectTemplatePayload{
		Name:              "Policy Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "policy-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	components, err := svc.ResolveOrUpsertSystemComponentsForEvidence(ResolveOrUpsertSystemComponentsForEvidenceInput{
		SystemSecurityPlanID: systemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Len(t, components, 1)
	require.NotNil(t, components[0].ID)

	var componentCount int64
	require.NoError(t, db.Table("system_components").Count(&componentCount).Error)
	require.Equal(t, int64(1), componentCount)
}

func TestSubjectTemplateService_ResolveOrUpsertSystemComponentsForEvidenceReturnsErrorWhenScanLimitHit(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)
	systemSecurityPlanID := createTestSystemSecurityPlanAndImplementation(t, db)

	for i := 0; i < maxRuntimeComponentTemplatesScan+1; i++ {
		_, err := svc.Create(SubjectTemplatePayload{
			Name:              fmt.Sprintf("Runtime Component %d", i),
			Type:              "component",
			IdentityLabelKeys: []string{"asset_id", "cluster"},
			SourceMode:        "runtime-derived",
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "plugin", Value: "github"},
			},
			LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
				{Key: "asset_id"},
				{Key: "cluster"},
			},
		})
		require.NoError(t, err)
	}

	_, err := svc.ResolveOrUpsertSystemComponentsForEvidence(ResolveOrUpsertSystemComponentsForEvidenceInput{
		SystemSecurityPlanID: systemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "reached scan limit")
}

func TestSubjectTemplateService_ResolveOrUpsertSystemComponentScopesIdentityBySystem(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	firstSystemSecurityPlanID := createTestSystemSecurityPlanAndImplementation(t, db)
	secondSystemSecurityPlanID := createTestSystemSecurityPlanAndImplementation(t, db)

	template, err := svc.Create(validSubjectTemplatePayload())
	require.NoError(t, err)

	first, err := svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID:    *template.ID,
		SystemSecurityPlanID: firstSystemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)

	second, err := svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID:    *template.ID,
		SystemSecurityPlanID: secondSystemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, *first.ID, *second.ID)

	var componentCount int64
	require.NoError(t, db.Table("system_components").Count(&componentCount).Error)
	require.Equal(t, int64(2), componentCount)
}

func TestSubjectTemplateService_ResolveOrUpsertAssessmentSubjectRecoversFromStaleIdentity(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	template, err := svc.Create(validSubjectTemplatePayload())
	require.NoError(t, err)

	first, err := svc.ResolveOrUpsertAssessmentSubject(ResolveOrUpsertAssessmentSubjectInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, first.ID)

	require.NoError(t, db.Table("assessment_subjects").Delete(&subjectResolverAssessmentSubjectRow{}, "id = ?", *first.ID).Error)

	second, err := svc.ResolveOrUpsertAssessmentSubject(ResolveOrUpsertAssessmentSubjectInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, second.ID)
	require.NotEqual(t, *first.ID, *second.ID)

	var identity AssessmentSubjectIdentity
	require.NoError(t, db.First(&identity).Error)
	require.Equal(t, *second.ID, identity.AssessmentSubjectID)
}

func TestSubjectTemplateService_ResolveOrUpsertSystemComponentRecoversFromStaleIdentity(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)
	systemSecurityPlanID := createTestSystemSecurityPlanAndImplementation(t, db)

	template, err := svc.Create(validSubjectTemplatePayload())
	require.NoError(t, err)

	first, err := svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID:    *template.ID,
		SystemSecurityPlanID: systemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, first.ID)

	require.NoError(t, db.Create(&riskrel.SystemComponentLabel{
		SystemComponentID: *first.ID,
		Key:               "orphan",
		Value:             "true",
	}).Error)

	require.NoError(t, db.Table("system_components").Delete(&subjectResolverSystemComponentRow{}, "id = ?", *first.ID).Error)

	second, err := svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID:    *template.ID,
		SystemSecurityPlanID: systemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, second.ID)
	require.NotEqual(t, *first.ID, *second.ID)

	var identity SystemComponentIdentity
	require.NoError(t, db.First(&identity).Error)
	require.Equal(t, *second.ID, identity.SystemComponentID)

	var orphanLabelCount int64
	require.NoError(t, db.Model(&riskrel.SystemComponentLabel{}).Where("system_component_id = ?", *first.ID).Count(&orphanLabelCount).Error)
	require.Equal(t, int64(0), orphanLabelCount)
}

func TestSubjectTemplateService_ValidationErrors(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	tests := []struct {
		name    string
		mutate  func(payload *SubjectTemplatePayload)
		message string
	}{
		{
			name: "invalid type",
			mutate: func(payload *SubjectTemplatePayload) {
				payload.Type = "invalid-type"
			},
			message: "invalid type",
		},
		{
			name: "invalid source mode",
			mutate: func(payload *SubjectTemplatePayload) {
				payload.SourceMode = "invalid-mode"
			},
			message: "invalid sourceMode",
		},
		{
			name: "identity key missing from label schema",
			mutate: func(payload *SubjectTemplatePayload) {
				payload.IdentityLabelKeys = []string{"asset_id", "namespace"}
			},
			message: "identityLabelKeys key \"namespace\" must exist in labelSchema",
		},
		{
			name: "duplicate selector label keys",
			mutate: func(payload *SubjectTemplatePayload) {
				payload.SelectorLabels = []SubjectTemplateSelectorLabelInput{
					{Key: "plugin", Value: "github"},
					{Key: "plugin", Value: "gitlab"},
				}
			},
			message: "selectorLabels contains duplicate keys",
		},
		{
			name: "selector labels required",
			mutate: func(payload *SubjectTemplatePayload) {
				payload.SelectorLabels = nil
			},
			message: "selectorLabels is required",
		},
		{
			name: "too many identity label keys",
			mutate: func(payload *SubjectTemplatePayload) {
				keys := make([]string, 0, maxSubjectTemplateIdentityKeys+1)
				schema := make([]SubjectTemplateLabelSchemaFieldInput, 0, maxSubjectTemplateIdentityKeys+1)
				for i := 0; i < maxSubjectTemplateIdentityKeys+1; i++ {
					key := fmt.Sprintf("asset_%d", i)
					keys = append(keys, key)
					schema = append(schema, SubjectTemplateLabelSchemaFieldInput{Key: key})
				}
				payload.IdentityLabelKeys = keys
				payload.LabelSchema = schema
			},
			message: "identityLabelKeys must contain at most 20 items",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := validSubjectTemplatePayload()
			tt.mutate(&payload)

			_, err := svc.Create(payload)
			require.Error(t, err)
			require.True(t, IsValidationError(err))
			require.Equal(t, tt.message, err.Error())
		})
	}

	template, err := svc.Create(validSubjectTemplatePayload())
	require.NoError(t, err)

	_, err = svc.ResolveOrUpsertAssessmentSubject(ResolveOrUpsertAssessmentSubjectInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-001"},
		},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.Equal(t, "identity label key \"cluster\" was not found in evidence labels", err.Error())

	_, err = svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID: *template.ID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-001"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.Equal(t, "systemSecurityPlanId is required", err.Error())
}

func newSubjectTemplateTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&SubjectTemplate{},
		&SubjectTemplateSelectorLabel{},
		&SubjectTemplateLabelSchemaField{},
		&EvidenceTemplateSubjectTemplate{},
		&AssessmentSubjectIdentity{},
		&SystemComponentIdentity{},
		&ComponentDefinitionIdentity{},
		&subjectResolverAssessmentSubjectRow{},
		&subjectResolverSystemComponentRow{},
		&subjectResolverSystemImplementationRow{},
		&relational.Metadata{},
		&relational.ComponentDefinition{},
		&relational.DefinedComponent{},
		&riskrel.AssessmentSubjectLabel{},
		&riskrel.SystemComponentLabel{},
		&riskrel.ComponentDefinitionLabel{},
	))

	return db
}

type subjectResolverAssessmentSubjectRow struct {
	relational.UUIDModel
	SSPID       *uuid.UUID                           `gorm:"column:sspid;type:uuid;index"`
	Type        string                               `gorm:"column:type"`
	Description *string                              `gorm:"column:description"`
	Remarks     *string                              `gorm:"column:remarks"`
	Props       datatypes.JSONSlice[relational.Prop] `gorm:"column:props;type:jsonb"`
	Links       datatypes.JSONSlice[relational.Link] `gorm:"column:links;type:jsonb"`
}

func (subjectResolverAssessmentSubjectRow) TableName() string {
	return "assessment_subjects"
}

type subjectResolverSystemComponentRow struct {
	relational.UUIDModel
	Type                   string                               `gorm:"column:type"`
	Title                  string                               `gorm:"column:title"`
	Description            string                               `gorm:"column:description"`
	Purpose                string                               `gorm:"column:purpose"`
	Remarks                string                               `gorm:"column:remarks"`
	Props                  datatypes.JSONSlice[relational.Prop] `gorm:"column:props;type:jsonb"`
	Links                  datatypes.JSONSlice[relational.Link] `gorm:"column:links;type:jsonb"`
	SystemImplementationID uuid.UUID                            `gorm:"column:system_implementation_id;type:uuid"`
	DefinedComponentID     *uuid.UUID                           `gorm:"column:defined_component_id;type:uuid"`
}

func (subjectResolverSystemComponentRow) TableName() string {
	return "system_components"
}

type subjectResolverSystemImplementationRow struct {
	relational.UUIDModel
	SystemSecurityPlanID uuid.UUID `gorm:"column:system_security_plan_id;type:uuid"`
}

func (subjectResolverSystemImplementationRow) TableName() string {
	return "system_implementations"
}

func createTestSystemSecurityPlanAndImplementation(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()

	systemSecurityPlanID := uuid.New()
	systemImplementationID := uuid.New()
	row := subjectResolverSystemImplementationRow{
		UUIDModel: relational.UUIDModel{
			ID: &systemImplementationID,
		},
		SystemSecurityPlanID: systemSecurityPlanID,
	}
	require.NoError(t, db.Create(&row).Error)

	return systemSecurityPlanID
}

func TestSubjectTemplateService_ResolveOrUpsertComponentDefinitionHappyPath(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	_, err := svc.Create(SubjectTemplatePayload{
		Name:              "GitHub Runtime Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	result, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.DefinedComponentIDs, 1)

	var cdCount int64
	require.NoError(t, db.Table("component_definitions").Count(&cdCount).Error)
	require.Equal(t, int64(1), cdCount)

	var dcCount int64
	require.NoError(t, db.Table("defined_components").Count(&dcCount).Error)
	require.Equal(t, int64(1), dcCount)

	var identityCount int64
	require.NoError(t, db.Model(&ComponentDefinitionIdentity{}).Count(&identityCount).Error)
	require.Equal(t, int64(1), identityCount)

	var labelCount int64
	require.NoError(t, db.Model(&riskrel.ComponentDefinitionLabel{}).Count(&labelCount).Error)
	require.Equal(t, int64(2), labelCount)

	var cd relational.ComponentDefinition
	require.NoError(t, db.Preload("Metadata").First(&cd).Error)
	require.Equal(t, "github components", cd.Metadata.Title)
	require.Equal(t, "1.0.0", cd.Metadata.Version)
	require.Equal(t, versioning.GetLatestSupportedVersion(), cd.Metadata.OscalVersion)
	require.NotNil(t, cd.Metadata.LastModified)
}

func TestSubjectTemplateService_ResolveOrUpsertComponentDefinitionIdempotent(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	_, err := svc.Create(SubjectTemplatePayload{
		Name:              "GitHub Runtime Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	labels := []relational.Labels{
		{Name: "_plugin", Value: "github"},
		{Name: "asset_id", Value: "srv-123"},
		{Name: "cluster", Value: "prod-us"},
	}

	first, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{EvidenceLabels: labels})
	require.NoError(t, err)
	require.Len(t, first.DefinedComponentIDs, 1)

	second, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{EvidenceLabels: labels})
	require.NoError(t, err)
	require.Len(t, second.DefinedComponentIDs, 1)
	require.Equal(t, first.DefinedComponentIDs[0], second.DefinedComponentIDs[0])

	var cdCount int64
	require.NoError(t, db.Table("component_definitions").Count(&cdCount).Error)
	require.Equal(t, int64(1), cdCount)

	var dcCount int64
	require.NoError(t, db.Table("defined_components").Count(&dcCount).Error)
	require.Equal(t, int64(1), dcCount)

	var componentDefinition relational.ComponentDefinition
	require.NoError(t, db.First(&componentDefinition).Error)
	var metadataCount int64
	require.NoError(t, db.Model(&relational.Metadata{}).Where("parent_id = ?", componentDefinition.ID.String()).Count(&metadataCount).Error)
	require.Equal(t, int64(1), metadataCount)
}

func TestSubjectTemplateService_ResolveOrUpsertComponentDefinitionPluginPrefilter(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	// Create a GitHub template
	_, err := svc.Create(SubjectTemplatePayload{
		Name:              "GitHub Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	// Create a GitLab template
	_, err = svc.Create(SubjectTemplatePayload{
		Name:              "GitLab Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "gitlab"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	// Evidence for GitHub only
	result, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.DefinedComponentIDs, 1)

	// Should only create one CD (GitHub), not GitLab
	var cdCount int64
	require.NoError(t, db.Table("component_definitions").Count(&cdCount).Error)
	require.Equal(t, int64(1), cdCount)
}

func TestSubjectTemplateService_ResolveOrUpsertComponentDefinitionGroupsByPlugin(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	_, err := svc.Create(SubjectTemplatePayload{
		Name:              "GitHub Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	first, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Len(t, first.DefinedComponentIDs, 1)

	second, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-456"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Len(t, second.DefinedComponentIDs, 1)

	var cdCount int64
	require.NoError(t, db.Table("component_definitions").Count(&cdCount).Error)
	require.Equal(t, int64(1), cdCount)

	var dcCount int64
	require.NoError(t, db.Table("defined_components").Count(&dcCount).Error)
	require.Equal(t, int64(2), dcCount)

	var cd relational.ComponentDefinition
	require.NoError(t, db.Preload("Metadata").First(&cd).Error)
	require.Equal(t, "github components", cd.Metadata.Title)
}

func TestSubjectTemplateService_ResolveOrUpsertComponentDefinitionNoPlugin(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	result, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
		},
	})
	require.NoError(t, err)
	require.Empty(t, result.DefinedComponentIDs)
}

func TestSubjectTemplateService_FindSystemComponentsByDefinedComponentIDs(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)
	systemSecurityPlanID := createTestSystemSecurityPlanAndImplementation(t, db)

	// Create a component template with _plugin selector
	template, err := svc.Create(SubjectTemplatePayload{
		Name:              "GitHub Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)

	// First, resolve a ComponentDefinition
	cdResult, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Len(t, cdResult.DefinedComponentIDs, 1)

	// No SystemComponents linked yet
	scs, err := svc.FindSystemComponentsByDefinedComponentIDs(cdResult.DefinedComponentIDs)
	require.NoError(t, err)
	require.Empty(t, scs)

	// Create a SystemComponent via the existing resolver
	sc, err := svc.ResolveOrUpsertSystemComponent(ResolveOrUpsertSystemComponentInput{
		SubjectTemplateID:    *template.ID,
		SystemSecurityPlanID: systemSecurityPlanID,
		EvidenceLabels: []relational.Labels{
			{Name: "asset_id", Value: "srv-123"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, sc)

	// Link the SystemComponent to the DefinedComponent
	require.NoError(t, db.Table("system_components").Where("id = ?", *sc.ID).Update("defined_component_id", cdResult.DefinedComponentIDs[0]).Error)

	// Now FindSystemComponentsByDefinedComponentIDs should return it
	scs, err = svc.FindSystemComponentsByDefinedComponentIDs(cdResult.DefinedComponentIDs)
	require.NoError(t, err)
	require.Len(t, scs, 1)
	require.Equal(t, *sc.ID, *scs[0].ID)
}

func TestSubjectTemplateService_FindSystemComponentsByDefinedComponentIDsEmpty(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	scs, err := svc.FindSystemComponentsByDefinedComponentIDs(nil)
	require.NoError(t, err)
	require.Nil(t, scs)

	scs, err = svc.FindSystemComponentsByDefinedComponentIDs([]uuid.UUID{})
	require.NoError(t, err)
	require.Nil(t, scs)
}

func TestSubjectTemplateService_ResolveOrUpsertComponentDefinitionWithTemplates(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	titleTemplate := "GitHub Repo: {{.asset_id}}"
	descriptionTemplate := "Repository {{.asset_id}} in cluster {{.cluster}}"
	purposeTemplate := "Source code management"
	remarksTemplate := "Managed by {{.cluster}} team"

	template, err := svc.Create(SubjectTemplatePayload{
		Name:                "GitHub Component",
		Type:                "component",
		TitleTemplate:       &titleTemplate,
		DescriptionTemplate: &descriptionTemplate,
		PurposeTemplate:     &purposeTemplate,
		RemarksTemplate:     &remarksTemplate,
		IdentityLabelKeys:   []string{"asset_id", "cluster"},
		SourceMode:          "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
			{Key: "cluster"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, template.TitleTemplate)
	require.Equal(t, titleTemplate, *template.TitleTemplate)

	result, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "my-repo"},
			{Name: "cluster", Value: "prod-us"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.DefinedComponentIDs, 1)

	var dc relational.DefinedComponent
	require.NoError(t, db.First(&dc, "id = ?", result.DefinedComponentIDs[0]).Error)
	require.Equal(t, "GitHub Repo: my-repo", dc.Title)
	require.Equal(t, "Repository my-repo in cluster prod-us", dc.Description)
	require.Equal(t, "Source code management", dc.Purpose)
	require.Equal(t, "Managed by prod-us team", dc.Remarks)
}

func TestSubjectTemplateService_CreateWithInvalidTemplate(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	invalidTemplate := "{{.invalid_key}}"
	_, err := svc.Create(SubjectTemplatePayload{
		Name:              "Invalid Template",
		Type:              "component",
		TitleTemplate:     &invalidTemplate,
		IdentityLabelKeys: []string{"asset_id"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "titleTemplate validation failed")
}

func TestSubjectTemplateService_CreateWithValidTemplateNoRender(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	template, err := svc.Create(SubjectTemplatePayload{
		Name:              "No Template Component",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "_plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "asset_id"},
		},
	})
	require.NoError(t, err)
	require.Nil(t, template.TitleTemplate)

	result, err := svc.ResolveOrUpsertComponentDefinition(ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "my-repo"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.DefinedComponentIDs, 1)

	var dc relational.DefinedComponent
	require.NoError(t, db.First(&dc, "id = ?", result.DefinedComponentIDs[0]).Error)
	require.Equal(t, "No Template Component", dc.Title)
	require.Equal(t, "", dc.Description)
}

func TestSubjectTemplateService_BatchUpsertCreateUpdateDelete(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	pluginID := "batch-plugin"

	firstID := uuid.New()
	secondID := uuid.New()

	item := func(id uuid.UUID, name string) BatchSubjectTemplateItem {
		return BatchSubjectTemplateItem{
			ID:                id,
			Name:              name,
			Type:              "component",
			SourceMode:        "runtime-derived",
			IdentityLabelKeys: []string{"asset_id"},
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
			LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
				{Key: "asset_id", Description: strPtr("Unique asset ID")},
			},
		}
	}

	// Round 1: create two templates.
	result, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		item(firstID, "Subject one"),
		item(secondID, "Subject two"),
	})
	require.NoError(t, err)
	require.Len(t, result.Created, 2)
	require.Empty(t, result.Updated)
	require.Empty(t, result.Deleted)

	createdIDs := make(map[uuid.UUID]bool)
	for _, row := range result.Created {
		createdIDs[*row.ID] = true
	}
	require.True(t, createdIDs[firstID])
	require.True(t, createdIDs[secondID])

	// Round 2: update first, drop second (deleted), create third.
	thirdID := uuid.New()
	updated := item(firstID, "Subject one updated")
	updated.IdentityLabelKeys = []string{"asset_id", "region"}
	updated.LabelSchema = append(updated.LabelSchema, SubjectTemplateLabelSchemaFieldInput{
		Key:         "region",
		Description: strPtr("Cloud region"),
	})

	result2, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		updated,
		item(thirdID, "Subject three"),
	})
	require.NoError(t, err)
	require.Len(t, result2.Updated, 1)
	require.Equal(t, firstID, *result2.Updated[0].ID)
	require.Equal(t, "Subject one updated", result2.Updated[0].Name)
	require.Len(t, result2.Updated[0].LabelSchema, 2)
	require.Len(t, result2.Created, 1)
	require.Equal(t, thirdID, *result2.Created[0].ID)
	require.Len(t, result2.Deleted, 1)
	require.Equal(t, secondID, result2.Deleted[0])
	// Confirm second template is gone.
	var count int64
	require.NoError(t, db.Model(&SubjectTemplate{}).Where("id = ?", secondID).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestSubjectTemplateService_BatchUpsertEmptyPayloadDeletesAll(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	pluginID := "delete-plugin"
	id1, id2 := uuid.New(), uuid.New()

	makeItem := func(id uuid.UUID, name string) BatchSubjectTemplateItem {
		return BatchSubjectTemplateItem{
			ID:                id,
			Name:              name,
			Type:              "component",
			SourceMode:        "runtime-derived",
			IdentityLabelKeys: []string{"asset_id"},
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
			LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
				{Key: "asset_id"},
			},
		}
	}

	_, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		makeItem(id1, "Delete subject one"),
		makeItem(id2, "Delete subject two"),
	})
	require.NoError(t, err)

	result, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{})
	require.NoError(t, err)
	require.Empty(t, result.Created)
	require.Empty(t, result.Updated)
	require.Len(t, result.Deleted, 2)

	var remaining int64
	require.NoError(t, db.Model(&SubjectTemplate{}).Count(&remaining).Error)
	require.Equal(t, int64(0), remaining)
}

func TestSubjectTemplateService_BatchUpsertAlwaysDeletesEvenIfReferenced(t *testing.T) {
	db := newSubjectTemplateTestDBWithEvidence(t)
	svc := NewSubjectTemplateService(db)

	pluginID := "always-delete-plugin"
	keepID := uuid.New()
	referencedID := uuid.New()

	makeItem := func(id uuid.UUID, name string) BatchSubjectTemplateItem {
		return BatchSubjectTemplateItem{
			ID:                id,
			Name:              name,
			Type:              "component",
			SourceMode:        "runtime-derived",
			IdentityLabelKeys: []string{"asset_id"},
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
			LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
				{Key: "asset_id"},
			},
		}
	}

	_, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		makeItem(keepID, "Keep me"),
		makeItem(referencedID, "Referenced but deleted"),
	})
	require.NoError(t, err)

	// Simulate a reference to referencedID via evidence template.
	require.NoError(t, db.Create(&EvidenceTemplateSubjectTemplate{
		EvidenceTemplateID: uuid.New(),
		SubjectTemplateID:  referencedID,
	}).Error)

	// Even though referencedID is referenced, it should be deleted (no in-use guard).
	result, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		makeItem(keepID, "Keep me updated"),
	})
	require.NoError(t, err)
	require.Len(t, result.Updated, 1)
	require.Empty(t, result.Created)
	require.Len(t, result.Deleted, 1)
	require.Equal(t, referencedID, result.Deleted[0])

	var count int64
	require.NoError(t, db.Model(&SubjectTemplate{}).Where("id = ?", referencedID).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestSubjectTemplateService_BatchUpsertSkipsUnchanged(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	pluginID := "unchanged-plugin"

	id1 := uuid.New()
	id2 := uuid.New()

	makeItem := func(id uuid.UUID, name string) BatchSubjectTemplateItem {
		return BatchSubjectTemplateItem{
			ID:                id,
			Name:              name,
			Type:              "component",
			SourceMode:        "runtime-derived",
			IdentityLabelKeys: []string{"asset_id"},
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
			LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
				{Key: "asset_id"},
			},
		}
	}

	// Round 1: create two templates.
	_, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		makeItem(id1, "Template One"),
		makeItem(id2, "Template Two"),
	})
	require.NoError(t, err)

	// Round 2: same payload — nothing should be updated.
	result, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		makeItem(id1, "Template One"),
		makeItem(id2, "Template Two"),
	})
	require.NoError(t, err)
	require.Empty(t, result.Created)
	require.Empty(t, result.Updated)
	require.Empty(t, result.Deleted)
	require.Len(t, result.Unchanged, 2)
	require.Contains(t, result.Unchanged, id1)
	require.Contains(t, result.Unchanged, id2)

	// Round 3: update only id1 — id2 should remain unchanged.
	result2, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		makeItem(id1, "Template One Modified"),
		makeItem(id2, "Template Two"),
	})
	require.NoError(t, err)
	require.Len(t, result2.Updated, 1)
	require.Equal(t, id1, *result2.Updated[0].ID)
	require.Empty(t, result2.Created)
	require.Empty(t, result2.Deleted)
	require.Len(t, result2.Unchanged, 1)
	require.Equal(t, id2, result2.Unchanged[0])
}

func TestSubjectTemplateService_BatchUpsertValidationErrors(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	pluginID := "batch-plugin"

	// Missing plugin ID.
	_, err := svc.BatchUpsert("", []BatchSubjectTemplateItem{})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	// Missing item ID (uuid.Nil).
	_, err = svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		{
			ID:         uuid.Nil,
			Name:       "No ID",
			Type:       "component",
			SourceMode: "runtime-derived",
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
		},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.Contains(t, err.Error(), "id is required")

	// Item with invalid payload (empty name).
	_, err = svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		{
			ID:         uuid.New(),
			Name:       "",
			Type:       "component",
			SourceMode: "runtime-derived",
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
		},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	// Duplicate ID.
	sharedID := uuid.New()
	_, err = svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		{
			ID:         sharedID,
			Name:       "First",
			Type:       "component",
			SourceMode: "runtime-derived",
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
		},
		{
			ID:         sharedID,
			Name:       "Second",
			Type:       "component",
			SourceMode: "runtime-derived",
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
		},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.Contains(t, err.Error(), "duplicate id")
}

func TestSubjectTemplateService_BatchUpsertIsolatesByPlugin(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	idA := uuid.New()
	idB := uuid.New()

	makeItem := func(id uuid.UUID, plugin string) BatchSubjectTemplateItem {
		return BatchSubjectTemplateItem{
			ID:                id,
			Name:              "Template for " + plugin,
			Type:              "component",
			SourceMode:        "runtime-derived",
			IdentityLabelKeys: []string{"asset_id"},
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: plugin},
			},
			LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
				{Key: "asset_id"},
			},
		}
	}

	_, err := svc.BatchUpsert("plugin-a", []BatchSubjectTemplateItem{makeItem(idA, "plugin-a")})
	require.NoError(t, err)

	_, err = svc.BatchUpsert("plugin-b", []BatchSubjectTemplateItem{makeItem(idB, "plugin-b")})
	require.NoError(t, err)

	// Empty batch for plugin-a should only delete plugin-a's template.
	result, err := svc.BatchUpsert("plugin-a", []BatchSubjectTemplateItem{})
	require.NoError(t, err)
	require.Len(t, result.Deleted, 1)
	require.Equal(t, idA, result.Deleted[0])

	// plugin-b's template must still exist.
	var count int64
	require.NoError(t, db.Model(&SubjectTemplate{}).Where("id = ?", idB).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestSubjectTemplateService_BatchUpsertDeleteCleansUpSelectorLabelsAndSchema(t *testing.T) {
	db := newSubjectTemplateTestDB(t)
	svc := NewSubjectTemplateService(db)

	pluginID := "cleanup-plugin"
	id := uuid.New()

	_, err := svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{
		{
			ID:                id,
			Name:              "Template with labels",
			Type:              "component",
			SourceMode:        "runtime-derived",
			IdentityLabelKeys: []string{"asset_id"},
			SelectorLabels: []SubjectTemplateSelectorLabelInput{
				{Key: "_plugin", Value: pluginID},
			},
			LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
				{Key: "asset_id", Description: strPtr("Asset ID")},
			},
		},
	})
	require.NoError(t, err)

	var selectorCount, schemaCount int64
	require.NoError(t, db.Model(&SubjectTemplateSelectorLabel{}).Where("subject_template_id = ?", id).Count(&selectorCount).Error)
	require.Equal(t, int64(1), selectorCount)
	require.NoError(t, db.Model(&SubjectTemplateLabelSchemaField{}).Where("subject_template_id = ?", id).Count(&schemaCount).Error)
	require.Equal(t, int64(1), schemaCount)

	// Delete via empty batch.
	_, err = svc.BatchUpsert(pluginID, []BatchSubjectTemplateItem{})
	require.NoError(t, err)

	require.NoError(t, db.Model(&SubjectTemplateSelectorLabel{}).Where("subject_template_id = ?", id).Count(&selectorCount).Error)
	require.Equal(t, int64(0), selectorCount)
	require.NoError(t, db.Model(&SubjectTemplateLabelSchemaField{}).Where("subject_template_id = ?", id).Count(&schemaCount).Error)
	require.Equal(t, int64(0), schemaCount)
}

func newSubjectTemplateTestDBWithEvidence(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&SubjectTemplate{},
		&SubjectTemplateSelectorLabel{},
		&SubjectTemplateLabelSchemaField{},
		&AssessmentSubjectIdentity{},
		&SystemComponentIdentity{},
		&ComponentDefinitionIdentity{},
		&subjectResolverAssessmentSubjectRow{},
		&subjectResolverSystemComponentRow{},
		&subjectResolverSystemImplementationRow{},
		&relational.Metadata{},
		&relational.ComponentDefinition{},
		&relational.DefinedComponent{},
		&riskrel.AssessmentSubjectLabel{},
		&riskrel.SystemComponentLabel{},
		&riskrel.ComponentDefinitionLabel{},
		&EvidenceTemplateSubjectTemplate{},
	))

	return db
}

func validSubjectTemplatePayload() SubjectTemplatePayload {
	return SubjectTemplatePayload{
		Name:              "Runtime component identity",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id", "cluster"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []SubjectTemplateSelectorLabelInput{
			{Key: "plugin", Value: "github"},
		},
		LabelSchema: []SubjectTemplateLabelSchemaFieldInput{
			{Key: "asset_id", Description: strPtr("Asset ID")},
			{Key: "cluster", Description: strPtr("Cluster")},
		},
	}
}
