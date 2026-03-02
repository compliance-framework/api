package templates

import (
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestEvidenceTemplateService_CreateListGetUpdate(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	created, err := svc.Create(EvidenceTemplatePayload{
		PluginID:      " github-repositories ",
		PolicyPackage: " compliance_framework.secret_scanning_enabled ",
		Title:         " Secret scanning status evidence ",
		Description:   " Captures secret scanning enablement status. ",
		Methods:       []string{" test "},
		IsActive:      boolPtr(true),
		SelectorLabels: []EvidenceTemplateSelectorLabelInput{
			{Key: " _policy ", Value: " compliance_framework.secret_scanning_enabled "},
			{Key: " plugin.id ", Value: " github-repositories "},
		},
		LabelSchema: []EvidenceTemplateLabelSchemaFieldInput{
			{Key: " github.org ", Description: strPtr(" GitHub organization login "), Required: true},
			{Key: " github.repo ", Description: strPtr(" GitHub repository full name "), Required: true},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.NotNil(t, created.ID)
	require.Equal(t, "github-repositories", created.PluginID)
	require.Equal(t, "compliance_framework.secret_scanning_enabled", created.PolicyPackage)
	require.Equal(t, "Secret scanning status evidence", created.Title)
	require.Equal(t, "Captures secret scanning enablement status.", created.Description)
	require.True(t, created.IsActive)
	require.Len(t, created.Methods, 1)
	require.Equal(t, "TEST", created.Methods[0])
	require.Len(t, created.SelectorLabels, 2)
	require.Equal(t, "_policy", created.SelectorLabels[0].Key)
	require.Len(t, created.LabelSchema, 2)
	require.True(t, created.LabelSchema[0].Required)

	filters := EvidenceTemplateListFilters{
		PluginID:      strPtr(" github-repositories "),
		PolicyPackage: strPtr(" compliance_framework.secret_scanning_enabled "),
		IsActive:      boolPtr(true),
	}
	rows, total, err := svc.List(EvidenceTemplateListParams{
		Filters: filters,
		Limit:   10,
		Offset:  0,
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, rows, 1)

	got, err := svc.GetByID(*created.ID)
	require.NoError(t, err)
	require.Equal(t, *created.ID, *got.ID)
	require.Len(t, got.SelectorLabels, 2)
	require.Len(t, got.LabelSchema, 2)

	updated, err := svc.Update(*created.ID, EvidenceTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "compliance_framework.secret_scanning_enabled",
		Title:         "Secret scanning status evidence updated",
		Description:   "Updated description.",
		Methods:       []string{"TEST", "EXAMINE"},
		IsActive:      boolPtr(false),
		SelectorLabels: []EvidenceTemplateSelectorLabelInput{
			{Key: "_policy", Value: "compliance_framework.secret_scanning_enabled"},
		},
		LabelSchema: []EvidenceTemplateLabelSchemaFieldInput{
			{Key: "github.org", Description: strPtr("GitHub organization login"), Required: true},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "Secret scanning status evidence updated", updated.Title)
	require.False(t, updated.IsActive)
	require.Len(t, updated.Methods, 2)
	require.Len(t, updated.SelectorLabels, 1)
	require.Len(t, updated.LabelSchema, 1)

	var selectorCount int64
	require.NoError(t, db.Model(&EvidenceTemplateSelectorLabel{}).Where("evidence_template_id = ?", *created.ID).Count(&selectorCount).Error)
	require.Equal(t, int64(1), selectorCount)

	var schemaCount int64
	require.NoError(t, db.Model(&EvidenceTemplateLabelSchemaField{}).Where("evidence_template_id = ?", *created.ID).Count(&schemaCount).Error)
	require.Equal(t, int64(1), schemaCount)
}

func TestEvidenceTemplateService_Delete(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	created, err := svc.Create(EvidenceTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "compliance_framework.secret_scanning_enabled",
		Title:         "Template to delete",
		SelectorLabels: []EvidenceTemplateSelectorLabelInput{
			{Key: "_policy", Value: "compliance_framework.secret_scanning_enabled"},
		},
		LabelSchema: []EvidenceTemplateLabelSchemaFieldInput{
			{Key: "github.org"},
		},
	})
	require.NoError(t, err)

	require.NoError(t, svc.Delete(*created.ID))

	_, err = svc.GetByID(*created.ID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	var selectorCount int64
	require.NoError(t, db.Model(&EvidenceTemplateSelectorLabel{}).Where("evidence_template_id = ?", *created.ID).Count(&selectorCount).Error)
	require.Equal(t, int64(0), selectorCount)

	var schemaCount int64
	require.NoError(t, db.Model(&EvidenceTemplateLabelSchemaField{}).Where("evidence_template_id = ?", *created.ID).Count(&schemaCount).Error)
	require.Equal(t, int64(0), schemaCount)
}

func TestEvidenceTemplateService_FindMatchesForEvidence(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	_, err := svc.Create(EvidenceTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "compliance_framework.secret_scanning_enabled",
		Title:         "Secret scanning template",
		SelectorLabels: []EvidenceTemplateSelectorLabelInput{
			{Key: "_policy", Value: "compliance_framework.secret_scanning_enabled"},
			{Key: "plugin.id", Value: "github-repositories"},
		},
		LabelSchema: []EvidenceTemplateLabelSchemaFieldInput{
			{Key: "github.org"},
		},
	})
	require.NoError(t, err)

	_, err = svc.Create(EvidenceTemplatePayload{
		PluginID:      "other-plugin",
		PolicyPackage: "other.policy",
		Title:         "Other template",
		SelectorLabels: []EvidenceTemplateSelectorLabelInput{
			{Key: "_policy", Value: "other.policy"},
		},
		LabelSchema: []EvidenceTemplateLabelSchemaFieldInput{
			{Key: "some.key"},
		},
	})
	require.NoError(t, err)

	matchingLabels := map[string]string{
		"_policy":   "compliance_framework.secret_scanning_enabled",
		"plugin.id": "github-repositories",
		"github.org": "my-org",
	}
	matches, err := svc.FindMatchesForEvidence(matchingLabels)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "Secret scanning template", matches[0].Title)

	nonMatchingLabels := map[string]string{
		"_policy": "some.other.policy",
	}
	noMatches, err := svc.FindMatchesForEvidence(nonMatchingLabels)
	require.NoError(t, err)
	require.Len(t, noMatches, 0)

	emptyLabels := map[string]string{}
	noMatchesEmpty, err := svc.FindMatchesForEvidence(emptyLabels)
	require.NoError(t, err)
	require.Len(t, noMatchesEmpty, 0)
}

func TestEvidenceTemplateService_CreateValidationErrors(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	tooLong := strings.Repeat("a", maxEvidenceTemplateFieldLength+1)

	tests := []struct {
		name    string
		mutate  func(payload *EvidenceTemplatePayload)
		message string
	}{
		{
			name: "missing pluginId",
			mutate: func(p *EvidenceTemplatePayload) {
				p.PluginID = ""
			},
			message: "pluginId is required",
		},
		{
			name: "missing policyPackage",
			mutate: func(p *EvidenceTemplatePayload) {
				p.PolicyPackage = ""
			},
			message: "policyPackage is required",
		},
		{
			name: "missing title",
			mutate: func(p *EvidenceTemplatePayload) {
				p.Title = ""
			},
			message: "title is required",
		},
		{
			name: "pluginId too long",
			mutate: func(p *EvidenceTemplatePayload) {
				p.PluginID = tooLong
			},
			message: "pluginId must be at most 1000 characters",
		},
		{
			name: "invalid method",
			mutate: func(p *EvidenceTemplatePayload) {
				p.Methods = []string{"INVALID"}
			},
			message: `invalid method "INVALID": must be one of TEST, EXAMINE, INTERVIEW`,
		},
		{
			name: "duplicate method",
			mutate: func(p *EvidenceTemplatePayload) {
				p.Methods = []string{"TEST", "TEST"}
			},
			message: "methods contains duplicate entries",
		},
		{
			name: "duplicate selectorLabels key",
			mutate: func(p *EvidenceTemplatePayload) {
				p.SelectorLabels = []EvidenceTemplateSelectorLabelInput{
					{Key: "_policy", Value: "val1"},
					{Key: "_policy", Value: "val2"},
				}
			},
			message: "selectorLabels contains duplicate keys",
		},
		{
			name: "duplicate labelSchema key",
			mutate: func(p *EvidenceTemplatePayload) {
				p.LabelSchema = []EvidenceTemplateLabelSchemaFieldInput{
					{Key: "github.org"},
					{Key: "github.org"},
				}
			},
			message: "labelSchema contains duplicate keys",
		},
		{
			name: "empty selectorLabels",
			mutate: func(p *EvidenceTemplatePayload) {
				p.SelectorLabels = nil
			},
			message: "selectorLabels is required",
		},
		{
			name: "duplicate riskTemplateIds",
			mutate: func(p *EvidenceTemplatePayload) {
				id := uuid.New()
				p.RiskTemplateIDs = []uuid.UUID{id, id}
			},
			message: "riskTemplateIds contains duplicate IDs",
		},
		{
			name: "duplicate subjectTemplateIds",
			mutate: func(p *EvidenceTemplatePayload) {
				id := uuid.New()
				p.SubjectTemplateIDs = []uuid.UUID{id, id}
			},
			message: "subjectTemplateIds contains duplicate IDs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := validEvidenceTemplatePayload()
			tt.mutate(&payload)

			_, err := svc.Create(payload)
			require.Error(t, err)
			require.True(t, IsValidationError(err))
			require.Equal(t, tt.message, err.Error())
		})
	}
}

func TestEvidenceTemplateService_LinkedIDsValidation(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	nonExistentID := uuid.New()
	payload := validEvidenceTemplatePayload()
	payload.RiskTemplateIDs = []uuid.UUID{nonExistentID}

	_, err := svc.Create(payload)
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.Equal(t, "one or more riskTemplateIds were not found", err.Error())
}

func TestEvidenceTemplateService_FindMatchesIsCaseInsensitive(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	_, err := svc.Create(EvidenceTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "compliance_framework.secret_scanning_enabled",
		Title:         "Case insensitive template",
		SelectorLabels: []EvidenceTemplateSelectorLabelInput{
			{Key: "_policy", Value: "compliance_framework.secret_scanning_enabled"},
			{Key: "plugin.id", Value: "github-repositories"},
		},
		LabelSchema: []EvidenceTemplateLabelSchemaFieldInput{
			{Key: "github.org"},
		},
	})
	require.NoError(t, err)

	// Keys and values come in with different casing — should still match (mirrors labelfilter lower())
	mixedCaseLabels := map[string]string{
		"_policy":   "Compliance_Framework.Secret_Scanning_Enabled",
		"plugin.id": "GitHub-Repositories",
	}
	matches, err := svc.FindMatchesForEvidence(mixedCaseLabels)
	require.NoError(t, err)
	require.Len(t, matches, 1, "expected case-insensitive match")

	// Exact case should also match
	exactCaseLabels := map[string]string{
		"_policy":   "compliance_framework.secret_scanning_enabled",
		"plugin.id": "github-repositories",
	}
	matchesExact, err := svc.FindMatchesForEvidence(exactCaseLabels)
	require.NoError(t, err)
	require.Len(t, matchesExact, 1)

	// Mixed-case KEYS should also match (keys normalized inside FindMatchesForEvidence, P2)
	mixedCaseKeyLabels := map[string]string{
		"_POLICY":   "compliance_framework.secret_scanning_enabled",
		"PLUGIN.ID": "github-repositories",
	}
	matchesMixedKey, err := svc.FindMatchesForEvidence(mixedCaseKeyLabels)
	require.NoError(t, err)
	require.Len(t, matchesMixedKey, 1, "expected case-insensitive key match")

	// Wrong value should not match
	wrongLabels := map[string]string{
		"_policy":   "compliance_framework.secret_scanning_enabled",
		"plugin.id": "totally-different-plugin",
	}
	noMatches, err := svc.FindMatchesForEvidence(wrongLabels)
	require.NoError(t, err)
	require.Empty(t, noMatches)
}

func TestEvidenceTemplateService_SelectorLabelsToFilter(t *testing.T) {
	selectors := []EvidenceTemplateSelectorLabel{
		{Key: "_policy", Value: "compliance_framework.secret_scanning_enabled"},
		{Key: "plugin.id", Value: "github-repositories"},
	}

	filter := SelectorLabelsToFilter(selectors)

	require.NotNil(t, filter.Scope)
	require.NotNil(t, filter.Scope.Query)
	require.Equal(t, "AND", filter.Scope.Query.Operator)
	require.Len(t, filter.Scope.Scopes, 2)

	require.NotNil(t, filter.Scope.Scopes[0].Condition)
	require.Equal(t, "_policy", filter.Scope.Scopes[0].Label)
	require.Equal(t, "=", filter.Scope.Scopes[0].Condition.Operator)
	require.Equal(t, "compliance_framework.secret_scanning_enabled", filter.Scope.Scopes[0].Value)

	require.NotNil(t, filter.Scope.Scopes[1].Condition)
	require.Equal(t, "plugin.id", filter.Scope.Scopes[1].Label)
}

func TestEvidenceTemplateService_SelectorLabelsToFilterEmpty(t *testing.T) {
	filter := SelectorLabelsToFilter(nil)
	require.Equal(t, labelfilter.Filter{}, filter)

	filterEmpty := SelectorLabelsToFilter([]EvidenceTemplateSelectorLabel{})
	require.Equal(t, labelfilter.Filter{}, filterEmpty)
}

func TestEvidenceTemplateService_DefaultIsActive(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	payload := validEvidenceTemplatePayload()
	payload.IsActive = nil

	created, err := svc.Create(payload)
	require.NoError(t, err)
	require.True(t, created.IsActive)
}

func TestEvidenceTemplateService_InactiveCreate(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	payload := validEvidenceTemplatePayload()
	payload.IsActive = boolPtr(false)

	created, err := svc.Create(payload)
	require.NoError(t, err)
	require.False(t, created.IsActive)
}

func TestEvidenceTemplateService_SelectorLabelsOrderedAsc(t *testing.T) {
	db := newEvidenceTemplateTestDB(t)
	svc := NewEvidenceTemplateService(db)

	payload := validEvidenceTemplatePayload()
	payload.SelectorLabels = []EvidenceTemplateSelectorLabelInput{
		{Key: "z_label", Value: "z"},
		{Key: "a_label", Value: "a"},
	}

	created, err := svc.Create(payload)
	require.NoError(t, err)
	require.Len(t, created.SelectorLabels, 2)
	require.Equal(t, "a_label", created.SelectorLabels[0].Key)
	require.Equal(t, "z_label", created.SelectorLabels[1].Key)
}

func newEvidenceTemplateTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&RiskTemplate{},
		&RiskTemplateThreatRef{},
		&RemediationTemplate{},
		&RemediationTask{},
		&SubjectTemplate{},
		&SubjectTemplateSelectorLabel{},
		&SubjectTemplateLabelSchemaField{},
		&EvidenceTemplate{},
		&EvidenceTemplateSelectorLabel{},
		&EvidenceTemplateLabelSchemaField{},
		&EvidenceTemplateRiskTemplate{},
		&EvidenceTemplateSubjectTemplate{},
	))

	return db
}

func validEvidenceTemplatePayload() EvidenceTemplatePayload {
	return EvidenceTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "compliance_framework.secret_scanning_enabled",
		Title:         "Secret scanning status evidence",
		Methods:       []string{"TEST"},
		SelectorLabels: []EvidenceTemplateSelectorLabelInput{
			{Key: "_policy", Value: "compliance_framework.secret_scanning_enabled"},
		},
		LabelSchema: []EvidenceTemplateLabelSchemaFieldInput{
			{Key: "github.org", Description: strPtr("GitHub organization login"), Required: true},
		},
	}
}
