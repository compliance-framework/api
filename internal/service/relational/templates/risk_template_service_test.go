package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRiskTemplateService_CreateListGetUpdate(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	created, err := svc.Create(RiskTemplatePayload{
		PluginID:       "github-repositories",
		PolicyPackage:  "compliance_framework.secret_scanning_enabled",
		Name:           "Secret scanning risk template",
		Title:          "Undetected secrets committed to repository",
		Statement:      "Secret scanning is disabled and secrets may leak.",
		LikelihoodHint: strPtr("medium"),
		ImpactHint:     strPtr("high"),
		ViolationIDs:   []string{"missing_secret_scanning"},
		IsActive:       boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-312",
				Title:      "Cleartext Storage of Sensitive Information",
				URL:        strPtr("https://cwe.mitre.org/data/definitions/312.html"),
			},
		},
		RemediationTemplate: &RemediationTemplateInput{
			Title:       "Enable secret scanning",
			Description: strPtr("Enable and verify scanning in repository settings."),
			Tasks: []RemediationTaskInput{
				{Title: "Enable in repository settings", OrderIndex: 1},
				{Title: "Run baseline scan", OrderIndex: 2},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.NotNil(t, created.ID)
	require.Len(t, created.ThreatRefs, 1)
	require.NotNil(t, created.RemediationTemplate)
	require.Len(t, created.RemediationTemplate.Tasks, 2)

	filters := RiskTemplateListFilters{
		PluginID:      strPtr("github-repositories"),
		PolicyPackage: strPtr("compliance_framework.secret_scanning_enabled"),
		IsActive:      boolPtr(true),
	}
	rows, total, err := svc.List(RiskTemplateListParams{
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
	require.Len(t, got.ThreatRefs, 1)
	require.NotNil(t, got.RemediationTemplate)
	require.Len(t, got.RemediationTemplate.Tasks, 2)

	updated, err := svc.Update(*created.ID, RiskTemplatePayload{
		PluginID:       "github-repositories",
		PolicyPackage:  "compliance_framework.secret_scanning_enabled",
		Name:           "Secret scanning risk template (updated)",
		Title:          "Undetected secrets committed to repository (updated)",
		Statement:      "Updated statement.",
		LikelihoodHint: strPtr("low"),
		ImpactHint:     strPtr("medium"),
		ViolationIDs:   []string{"missing_secret_scanning", "missing_push_protection"},
		IsActive:       boolPtr(false),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-200",
				Title:      "Exposure of Sensitive Information to an Unauthorized Actor",
			},
		},
		RemediationTemplate: &RemediationTemplateInput{
			Title: "Enable secret scanning and push protection",
			Tasks: []RemediationTaskInput{
				{Title: "Enable secret scanning", OrderIndex: 1},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "Secret scanning risk template (updated)", updated.Name)
	require.False(t, updated.IsActive)
	require.Len(t, updated.ThreatRefs, 1)
	require.Equal(t, "CWE-200", updated.ThreatRefs[0].ExternalID)
	require.NotNil(t, updated.RemediationTemplate)
	require.Equal(t, "Enable secret scanning and push protection", updated.RemediationTemplate.Title)
	require.Len(t, updated.RemediationTemplate.Tasks, 1)
}

func TestRiskTemplateService_ValidateViolationMatch(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	require.True(t, svc.ValidateViolationMatch(nil, "anything"))
	require.True(t, svc.ValidateViolationMatch([]string{}, "anything"))
	require.True(t, svc.ValidateViolationMatch([]string{"missing_secret_scanning"}, "missing_secret_scanning"))
	require.True(t, svc.ValidateViolationMatch([]string{"missing_secret_scanning"}, "MISSING_SECRET_SCANNING"))
	require.False(t, svc.ValidateViolationMatch([]string{"missing_secret_scanning"}, "another_violation"))
}

func TestRiskTemplateService_CreateValidationErrors(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	tooLong := strings.Repeat("a", maxRiskTemplateFieldLength+1)
	tests := []struct {
		name    string
		mutate  func(payload *RiskTemplatePayload)
		message string
	}{
		{
			name: "invalid likelihood hint",
			mutate: func(payload *RiskTemplatePayload) {
				payload.LikelihoodHint = strPtr("critical")
			},
			message: "invalid likelihoodHint",
		},
		{
			name: "plugin id over max length",
			mutate: func(payload *RiskTemplatePayload) {
				payload.PluginID = tooLong
			},
			message: "pluginId must be at most 1000 characters",
		},
		{
			name: "too many threat refs",
			mutate: func(payload *RiskTemplatePayload) {
				payload.ThreatRefs = make([]ThreatRefInput, 0, maxThreatRefsPerTemplate+1)
				for i := 0; i < maxThreatRefsPerTemplate+1; i++ {
					payload.ThreatRefs = append(payload.ThreatRefs, ThreatRefInput{
						System:     "https://cwe.mitre.org",
						ExternalID: "CWE-" + strings.Repeat("1", i+1),
						Title:      "Threat",
					})
				}
			},
			message: "threatIds must contain at most 50 items",
		},
		{
			name: "too many violation ids",
			mutate: func(payload *RiskTemplatePayload) {
				payload.ViolationIDs = make([]string, 0, maxViolationIDsPerTemplate+1)
				for i := 0; i < maxViolationIDsPerTemplate+1; i++ {
					payload.ViolationIDs = append(payload.ViolationIDs, "violation-id")
				}
			},
			message: "violationIds must contain at most 100 items",
		},
		{
			name: "duplicate threat refs",
			mutate: func(payload *RiskTemplatePayload) {
				payload.ThreatRefs = append(payload.ThreatRefs, payload.ThreatRefs[0])
			},
			message: "threatIds contains duplicate system/id pairs",
		},
		{
			name: "duplicate remediation order index",
			mutate: func(payload *RiskTemplatePayload) {
				payload.RemediationTemplate = &RemediationTemplateInput{
					Title: "Remediation",
					Tasks: []RemediationTaskInput{
						{Title: "Task one", OrderIndex: 1},
						{Title: "Task two", OrderIndex: 1},
					},
				}
			},
			message: "remediationTemplate.tasks.orderIndex must be unique",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := validRiskTemplatePayload()
			tt.mutate(&payload)

			_, err := svc.Create(payload)
			require.Error(t, err)
			require.True(t, IsValidationError(err))
			require.Equal(t, tt.message, err.Error())
		})
	}
}

func TestRiskTemplateService_Delete(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	created, err := svc.Create(RiskTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "compliance_framework.secret_scanning_enabled",
		Name:          "Template to delete",
		Title:         "Template to delete",
		Statement:     "Template to delete.",
		IsActive:      boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-312",
				Title:      "Cleartext Storage of Sensitive Information",
			},
		},
		RemediationTemplate: &RemediationTemplateInput{
			Title: "Delete remediation",
			Tasks: []RemediationTaskInput{
				{Title: "Delete task", OrderIndex: 1},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created.RemediationTemplate)

	require.NoError(t, svc.Delete(*created.ID))

	_, err = svc.GetByID(*created.ID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	var remediationCount int64
	require.NoError(t, db.Model(&RemediationTemplate{}).Where("id = ?", *created.RemediationTemplateID).Count(&remediationCount).Error)
	require.Equal(t, int64(0), remediationCount)

	var threatRefCount int64
	require.NoError(t, db.Model(&RiskTemplateThreatRef{}).Where("risk_template_id = ?", *created.ID).Count(&threatRefCount).Error)
	require.Equal(t, int64(0), threatRefCount)

	var remediationTaskCount int64
	require.NoError(t, db.Model(&RemediationTask{}).Where("remediation_template_id = ?", *created.RemediationTemplateID).Count(&remediationTaskCount).Error)
	require.Equal(t, int64(0), remediationTaskCount)
}

func TestRiskTemplateService_CreateTrimsRiskLevelHints(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	created, err := svc.Create(RiskTemplatePayload{
		PluginID:       "github-repositories",
		PolicyPackage:  "compliance_framework.secret_scanning_enabled",
		Name:           "Template with trimmed levels",
		Title:          "Template with trimmed levels",
		Statement:      "Template statement.",
		LikelihoodHint: strPtr(" low "),
		ImpactHint:     strPtr(" high "),
		IsActive:       boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-312",
				Title:      "Cleartext Storage of Sensitive Information",
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created.LikelihoodHint)
	require.NotNil(t, created.ImpactHint)
	require.Equal(t, "low", *created.LikelihoodHint)
	require.Equal(t, "high", *created.ImpactHint)
}

func TestRiskTemplateService_CreateNormalizesEmptyRiskLevelHints(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	created, err := svc.Create(RiskTemplatePayload{
		PluginID:       "github-repositories",
		PolicyPackage:  "compliance_framework.secret_scanning_enabled",
		Name:           "Template with empty levels",
		Title:          "Template with empty levels",
		Statement:      "Template statement.",
		LikelihoodHint: strPtr("   "),
		ImpactHint:     strPtr("\t"),
		IsActive:       boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-312",
				Title:      "Cleartext Storage of Sensitive Information",
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created.LikelihoodHint)
	require.NotNil(t, created.ImpactHint)
	require.Equal(t, "", *created.LikelihoodHint)
	require.Equal(t, "", *created.ImpactHint)
}

func newRiskTemplateTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&RiskTemplate{},
		&RiskTemplateThreatRef{},
		&RemediationTemplate{},
		&RemediationTask{},
	))

	return db
}

func strPtr(v string) *string {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}

func validRiskTemplatePayload() RiskTemplatePayload {
	return RiskTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "compliance_framework.secret_scanning_enabled",
		Name:          "Secret scanning risk template",
		Title:         "Undetected secrets committed to repository",
		Statement:     "Secret scanning is disabled and secrets may leak.",
		ViolationIDs:  []string{"missing_secret_scanning"},
		IsActive:      boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-312",
				Title:      "Cleartext Storage of Sensitive Information",
			},
		},
	}
}
