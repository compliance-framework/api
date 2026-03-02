package templates

import (
	"fmt"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
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
		&AssessmentSubjectIdentity{},
		&SystemComponentIdentity{},
		&subjectResolverAssessmentSubjectRow{},
		&subjectResolverSystemComponentRow{},
		&subjectResolverSystemImplementationRow{},
		&riskrel.AssessmentSubjectLabel{},
		&riskrel.SystemComponentLabel{},
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
