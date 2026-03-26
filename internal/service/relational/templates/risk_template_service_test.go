package templates

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRiskTemplateService_CreateListGetUpdate(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	created, err := svc.Create(RiskTemplatePayload{
		PluginID:       " github-repositories ",
		PolicyPackage:  " compliance_framework.secret_scanning_enabled ",
		Name:           " Secret scanning risk template ",
		Title:          " Undetected secrets committed to repository ",
		Statement:      " Secret scanning is disabled and secrets may leak. ",
		LikelihoodHint: strPtr("medium"),
		ImpactHint:     strPtr("high"),
		ViolationIDs:   []string{" missing_secret_scanning "},
		IsActive:       boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     " https://cwe.mitre.org ",
				ExternalID: " CWE-312 ",
				Title:      " Cleartext Storage of Sensitive Information ",
				URL:        strPtr(" https://cwe.mitre.org/data/definitions/312.html "),
			},
		},
		RemediationTemplate: &RemediationTemplateInput{
			Title:       " Enable secret scanning ",
			Description: strPtr(" Enable and verify scanning in repository settings. "),
			Tasks: []RemediationTaskInput{
				{Title: " Enable in repository settings ", OrderIndex: 1},
				{Title: " Run baseline scan ", OrderIndex: 2},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.NotNil(t, created.ID)
	require.Len(t, created.ThreatRefs, 1)
	require.NotNil(t, created.RemediationTemplate)
	require.Len(t, created.RemediationTemplate.Tasks, 2)
	require.Equal(t, "github-repositories", created.PluginID)
	require.Equal(t, "compliance_framework.secret_scanning_enabled", created.PolicyPackage)
	require.Equal(t, "Secret scanning risk template", created.Name)
	require.Equal(t, "Undetected secrets committed to repository", created.Title)
	require.Equal(t, "Secret scanning is disabled and secrets may leak.", created.Statement)
	require.NotNil(t, created.LikelihoodHint)
	require.Equal(t, "moderate", *created.LikelihoodHint)
	require.NotNil(t, created.ImpactHint)
	require.Equal(t, "high", *created.ImpactHint)
	require.Equal(t, "missing_secret_scanning", created.ViolationIDs[0])
	require.Equal(t, "https://cwe.mitre.org", created.ThreatRefs[0].System)
	require.Equal(t, "CWE-312", created.ThreatRefs[0].ExternalID)
	require.Equal(t, "Cleartext Storage of Sensitive Information", created.ThreatRefs[0].Title)
	require.NotNil(t, created.ThreatRefs[0].URL)
	require.Equal(t, "https://cwe.mitre.org/data/definitions/312.html", *created.ThreatRefs[0].URL)
	require.Equal(t, "Enable secret scanning", created.RemediationTemplate.Title)
	require.NotNil(t, created.RemediationTemplate.Description)
	require.Equal(t, "Enable and verify scanning in repository settings.", *created.RemediationTemplate.Description)
	require.Equal(t, "Enable in repository settings", created.RemediationTemplate.Tasks[0].Title)
	require.Equal(t, "Run baseline scan", created.RemediationTemplate.Tasks[1].Title)

	filters := RiskTemplateListFilters{
		PluginID:      strPtr(" github-repositories "),
		PolicyPackage: strPtr(" compliance_framework.secret_scanning_enabled "),
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
		PluginID:       " github-repositories ",
		PolicyPackage:  " compliance_framework.secret_scanning_enabled ",
		Name:           " Secret scanning risk template (updated) ",
		Title:          " Undetected secrets committed to repository (updated) ",
		Statement:      " Updated statement. ",
		LikelihoodHint: strPtr("low"),
		ImpactHint:     strPtr("medium"),
		ViolationIDs:   []string{" missing_secret_scanning ", " missing_push_protection "},
		IsActive:       boolPtr(false),
		ThreatRefs: []ThreatRefInput{
			{
				System:     " https://cwe.mitre.org ",
				ExternalID: " CWE-200 ",
				Title:      " Exposure of Sensitive Information to an Unauthorized Actor ",
			},
		},
		RemediationTemplate: &RemediationTemplateInput{
			Title: " Enable secret scanning and push protection ",
			Tasks: []RemediationTaskInput{
				{Title: " Enable secret scanning ", OrderIndex: 1},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "Secret scanning risk template (updated)", updated.Name)
	require.NotNil(t, updated.ImpactHint)
	require.Equal(t, "moderate", *updated.ImpactHint)
	require.False(t, updated.IsActive)
	require.Len(t, updated.ThreatRefs, 1)
	require.Equal(t, "CWE-200", updated.ThreatRefs[0].ExternalID)
	require.NotNil(t, updated.RemediationTemplate)
	require.Equal(t, "Enable secret scanning and push protection", updated.RemediationTemplate.Title)
	require.Len(t, updated.RemediationTemplate.Tasks, 1)
	require.Equal(t, "Enable secret scanning", updated.RemediationTemplate.Tasks[0].Title)
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
				payload.LikelihoodHint = strPtr("invalid")
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
			name: "violation ids cannot be empty",
			mutate: func(payload *RiskTemplatePayload) {
				payload.ViolationIDs = []string{"   "}
			},
			message: "violationIds entries must be non-empty",
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

func TestRiskTemplateService_PolicyPackageNormalization(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	// Create with mixed case and whitespace
	created, err := svc.Create(RiskTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "  Compliance_Framework.Secret_Scanning_Enabled  ",
		Name:          "Test template",
		Title:         "Test template",
		Statement:     "Test statement.",
		ViolationIDs:  []string{"violation-1"},
		IsActive:      boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-312",
				Title:      "Test",
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "compliance_framework.secret_scanning_enabled", created.PolicyPackage)

	// Update with different case
	updated, err := svc.Update(*created.ID, RiskTemplatePayload{
		PluginID:      "github-repositories",
		PolicyPackage: "  COMPLIANCE_FRAMEWORK.SECRET_SCANNING_ENABLED  ",
		Name:          "Test template updated",
		Title:         "Test template updated",
		Statement:     "Test statement updated.",
		ViolationIDs:  []string{"violation-1"},
		IsActive:      boolPtr(true),
		ThreatRefs: []ThreatRefInput{
			{
				System:     "https://cwe.mitre.org",
				ExternalID: "CWE-312",
				Title:      "Test",
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "compliance_framework.secret_scanning_enabled", updated.PolicyPackage)

	// List with different case should find it
	rows, total, err := svc.List(RiskTemplateListParams{
		Filters: RiskTemplateListFilters{
			PolicyPackage: strPtr("  Compliance_Framework.Secret_Scanning_Enabled  "),
		},
		Limit:  10,
		Offset: 0,
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, rows, 1)
	require.Equal(t, "compliance_framework.secret_scanning_enabled", rows[0].PolicyPackage)
}

func TestRiskTemplateService_BatchUpsertCreateUpdateDelete(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	pluginID := "batch-plugin"
	policy := "compliance_framework.batch_test"

	firstID := uuid.New()
	secondID := uuid.New()

	// Round 1: create two templates.
	result, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{
			ID:        firstID,
			Name:      "Batch one",
			Title:     "Batch title one",
			Statement: "Batch statement one",
		},
		{
			ID:        secondID,
			Name:      "Batch two",
			Title:     "Batch title two",
			Statement: "Batch statement two",
		},
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
	result2, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{
			ID:        firstID,
			Name:      "Batch one updated",
			Title:     "Batch title one updated",
			Statement: "Batch statement one updated",
			ThreatRefs: []ThreatRefInput{
				{System: "https://cwe.mitre.org", ExternalID: "CWE-312", Title: "Cleartext Storage"},
			},
		},
		{
			ID:        thirdID,
			Name:      "Batch three",
			Title:     "Batch title three",
			Statement: "Batch statement three",
		},
	})
	require.NoError(t, err)
	require.Len(t, result2.Updated, 1)
	require.Equal(t, firstID, *result2.Updated[0].ID)
	require.Equal(t, "Batch one updated", result2.Updated[0].Name)
	require.Len(t, result2.Updated[0].ThreatRefs, 1)
	require.Len(t, result2.Created, 1)
	require.Equal(t, thirdID, *result2.Created[0].ID)
	require.Len(t, result2.Deleted, 1)
	require.Equal(t, secondID, result2.Deleted[0])
	// Confirm second template is gone from the DB.
	var count int64
	require.NoError(t, db.Model(&RiskTemplate{}).Where("id = ?", secondID).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestRiskTemplateService_BatchUpsertEmptyPayloadDeletesAll(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	pluginID := "delete-plugin"
	policy := "compliance_framework.delete_test"

	id1, id2 := uuid.New(), uuid.New()
	_, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: id1, Name: "Delete me one", Title: "T", Statement: "S"},
		{ID: id2, Name: "Delete me two", Title: "T", Statement: "S"},
	})
	require.NoError(t, err)

	result, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{})
	require.NoError(t, err)
	require.Empty(t, result.Created)
	require.Empty(t, result.Updated)
	require.Len(t, result.Deleted, 2)

	var remaining int64
	require.NoError(t, db.Model(&RiskTemplate{}).
		Where("plugin_id = ? AND policy_package = ?", pluginID, policy).
		Count(&remaining).Error)
	require.Equal(t, int64(0), remaining)
}

func TestRiskTemplateService_BatchUpsertAlwaysDeletesEvenIfReferenced(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	pluginID := "always-delete-plugin"
	policy := "compliance_framework.always_delete_test"

	keepID := uuid.New()
	referencedID := uuid.New()

	_, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: keepID, Name: "Keep me", Title: "T", Statement: "S"},
		{ID: referencedID, Name: "Referenced but deleted", Title: "T", Statement: "S"},
	})
	require.NoError(t, err)

	// Even though referencedID exists, it should be deleted (no in-use guard).
	result, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: keepID, Name: "Keep me updated", Title: "T updated", Statement: "S updated"},
	})
	require.NoError(t, err)
	require.Len(t, result.Updated, 1)
	require.Empty(t, result.Created)
	require.Len(t, result.Deleted, 1)
	require.Equal(t, referencedID, result.Deleted[0])

	var count int64
	require.NoError(t, db.Model(&RiskTemplate{}).Where("id = ?", referencedID).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestRiskTemplateService_BatchUpsertSkipsUnchanged(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	pluginID := "unchanged-plugin"
	policy := "compliance_framework.unchanged_test"

	id1 := uuid.New()
	id2 := uuid.New()

	// Round 1: create two templates.
	_, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: id1, Name: "Template One", Title: "T1", Statement: "S1"},
		{ID: id2, Name: "Template Two", Title: "T2", Statement: "S2"},
	})
	require.NoError(t, err)

	// Round 2: same payload — nothing should be updated.
	result, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: id1, Name: "Template One", Title: "T1", Statement: "S1"},
		{ID: id2, Name: "Template Two", Title: "T2", Statement: "S2"},
	})
	require.NoError(t, err)
	require.Empty(t, result.Created)
	require.Empty(t, result.Updated)
	require.Empty(t, result.Deleted)
	require.Len(t, result.Unchanged, 2)
	require.Contains(t, result.Unchanged, id1)
	require.Contains(t, result.Unchanged, id2)

	// Round 3: update only id1 — id2 should still be unchanged.
	result2, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: id1, Name: "Template One Modified", Title: "T1", Statement: "S1"},
		{ID: id2, Name: "Template Two", Title: "T2", Statement: "S2"},
	})
	require.NoError(t, err)
	require.Len(t, result2.Updated, 1)
	require.Equal(t, id1, *result2.Updated[0].ID)
	require.Empty(t, result2.Created)
	require.Empty(t, result2.Deleted)
	require.Len(t, result2.Unchanged, 1)
	require.Equal(t, id2, result2.Unchanged[0])
}

func TestRiskTemplateService_BatchUpsertValidationErrors(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	pluginID := "batch-plugin"
	policy := "compliance_framework.batch_test"

	// Missing ID (uuid.Nil).
	_, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: uuid.Nil, Name: "No ID", Title: "T", Statement: "S"},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.Contains(t, err.Error(), "id is required")

	// Missing plugin ID.
	_, err = svc.BatchUpsert("", policy, []BatchRiskTemplateItem{})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	// Missing policy package.
	_, err = svc.BatchUpsert(pluginID, "", []BatchRiskTemplateItem{})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	// Item with invalid payload (empty name).
	_, err = svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: uuid.New(), Name: "", Title: "T", Statement: "S"},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	// Duplicate ID.
	sharedID := uuid.New()
	_, err = svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{ID: sharedID, Name: "First", Title: "T", Statement: "S"},
		{ID: sharedID, Name: "Second", Title: "T", Statement: "S"},
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.Contains(t, err.Error(), "duplicate id")
}

func TestRiskTemplateService_BatchUpsertIsolatesByScope(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	idA := uuid.New()
	idB := uuid.New()

	// Seed one template in scope A and one in scope B.
	_, err := svc.BatchUpsert("plugin-a", "pkg.a", []BatchRiskTemplateItem{
		{ID: idA, Name: "Scope A template", Title: "T", Statement: "S"},
	})
	require.NoError(t, err)

	_, err = svc.BatchUpsert("plugin-b", "pkg.b", []BatchRiskTemplateItem{
		{ID: idB, Name: "Scope B template", Title: "T", Statement: "S"},
	})
	require.NoError(t, err)

	// Batch upsert for scope A with empty list should only delete scope A.
	result, err := svc.BatchUpsert("plugin-a", "pkg.a", []BatchRiskTemplateItem{})
	require.NoError(t, err)
	require.Len(t, result.Deleted, 1)
	require.Equal(t, idA, result.Deleted[0])

	// Scope B template must still exist.
	var count int64
	require.NoError(t, db.Model(&RiskTemplate{}).Where("id = ?", idB).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestRiskTemplateService_BatchUpsertDeleteCleansUpDependentRows(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	pluginID := "cleanup-plugin"
	policy := "compliance_framework.cleanup_test"
	id := uuid.New()

	// Create with threat refs and remediation.
	_, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{
			ID:        id,
			Name:      "Template with deps",
			Title:     "T",
			Statement: "S",
			ThreatRefs: []ThreatRefInput{
				{System: "https://cwe.mitre.org", ExternalID: "CWE-312", Title: "Cleartext Storage"},
			},
			RemediationTemplate: &RemediationTemplateInput{
				Title: "Fix it",
				Tasks: []RemediationTaskInput{
					{Title: "Step 1", OrderIndex: 1},
				},
			},
		},
	})
	require.NoError(t, err)

	// Confirm dependent rows were created.
	var threatCount, remCount int64
	require.NoError(t, db.Model(&RiskTemplateThreatRef{}).Where("risk_template_id = ?", id).Count(&threatCount).Error)
	require.Equal(t, int64(1), threatCount)
	var tmpl RiskTemplate
	require.NoError(t, db.First(&tmpl, "id = ?", id).Error)
	require.NotNil(t, tmpl.RemediationTemplateID)

	// Delete via empty batch.
	_, err = svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{})
	require.NoError(t, err)

	// Dependent rows must be gone.
	require.NoError(t, db.Model(&RiskTemplateThreatRef{}).Where("risk_template_id = ?", id).Count(&threatCount).Error)
	require.Equal(t, int64(0), threatCount)
	require.NoError(t, db.Model(&RemediationTemplate{}).Where("id = ?", tmpl.RemediationTemplateID).Count(&remCount).Error)
	require.Equal(t, int64(0), remCount)
}

func newRiskTemplateTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&RiskTemplate{},
		&RiskTemplateThreatRef{},
		&RiskTemplateLabelSchemaField{},
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

func TestRiskTemplateService_CreateWithLabelSchemaAndTemplateCapableFields(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	titleTmpl := " Vulnerability {{.cve_id}} found in {{.repo_name}} "
	stmtTmpl := "CVE {{.cve_id}} with severity {{.severity}} detected."
	desc := " The CVE identifier "

	created, err := svc.Create(RiskTemplatePayload{
		PluginID:      "vuln-scanner",
		PolicyPackage: "compliance_framework.vulnerability_scan",
		Name:          "CVE risk template",
		Title:         titleTmpl,
		Statement:     stmtTmpl,
		IsActive:      boolPtr(true),
		LabelSchema: []RiskTemplateLabelSchemaFieldInput{
			{Key: "cve_id", Description: &desc},
			{Key: "repo_name"},
			{Key: "severity"},
		},
		DedupeLabelKeys: []string{"cve_id"},
		ThreatRefs: []ThreatRefInput{
			{System: "https://cve.mitre.org", ExternalID: "CVE-2024-0001", Title: "Test CVE"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify label schema persisted
	require.Len(t, created.LabelSchema, 3)
	require.Equal(t, "cve_id", created.LabelSchema[0].Key) // sorted by key ASC
	require.NotNil(t, created.LabelSchema[0].Description)
	require.Equal(t, "The CVE identifier", *created.LabelSchema[0].Description)
	require.Equal(t, "repo_name", created.LabelSchema[1].Key)
	require.Equal(t, "severity", created.LabelSchema[2].Key)

	require.Equal(t, "Vulnerability {{.cve_id}} found in {{.repo_name}}", created.Title)
	require.Equal(t, stmtTmpl, created.Statement)

	// Verify dedupe label keys persisted
	require.Len(t, created.DedupeLabelKeys, 1)
	require.Equal(t, "cve_id", created.DedupeLabelKeys[0])

	// Verify round-trip via GetByID
	got, err := svc.GetByID(*created.ID)
	require.NoError(t, err)
	require.Len(t, got.LabelSchema, 3)
	require.Len(t, got.DedupeLabelKeys, 1)

	// Update: replace label schema and template-capable fields
	newTitleTmpl := "Issue {{.issue_id}} in {{.repo_name}}"
	updated, err := svc.Update(*created.ID, RiskTemplatePayload{
		PluginID:      "vuln-scanner",
		PolicyPackage: "compliance_framework.vulnerability_scan",
		Name:          "CVE risk template (updated)",
		Title:         newTitleTmpl,
		Statement:     "A vulnerability was detected.",
		IsActive:      boolPtr(true),
		LabelSchema: []RiskTemplateLabelSchemaFieldInput{
			{Key: "issue_id"},
			{Key: "repo_name"},
		},
		DedupeLabelKeys: []string{"issue_id"},
		ThreatRefs: []ThreatRefInput{
			{System: "https://cve.mitre.org", ExternalID: "CVE-2024-0001", Title: "Test CVE"},
		},
	})
	require.NoError(t, err)
	require.Len(t, updated.LabelSchema, 2)
	require.Equal(t, "issue_id", updated.LabelSchema[0].Key)
	require.Equal(t, "repo_name", updated.LabelSchema[1].Key)
	require.Equal(t, newTitleTmpl, updated.Title)
	require.Equal(t, "A vulnerability was detected.", updated.Statement)
	require.Len(t, updated.DedupeLabelKeys, 1)
	require.Equal(t, "issue_id", updated.DedupeLabelKeys[0])

	// Verify old label schema fields are gone from DB
	var oldSchemaCount int64
	require.NoError(t, db.Model(&RiskTemplateLabelSchemaField{}).
		Where("risk_template_id = ? AND key = ?", *created.ID, "cve_id").
		Count(&oldSchemaCount).Error)
	require.Equal(t, int64(0), oldSchemaCount)
}

func TestRiskTemplateService_TemplateCapableFieldValidation(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	tests := []struct {
		name    string
		mutate  func(payload *RiskTemplatePayload)
		message string
	}{
		{
			name: "template field reference without label schema",
			mutate: func(payload *RiskTemplatePayload) {
				payload.Title = "{{.some_key}}"
			},
			message: `title: template references undefined label key: "some_key" (not in label schema)`,
		},
		{
			name: "template field referencing undefined key",
			mutate: func(payload *RiskTemplatePayload) {
				payload.Title = "{{.undefined_key}}"
				payload.LabelSchema = []RiskTemplateLabelSchemaFieldInput{
					{Key: "defined_key"},
				}
			},
			message: `title: template references undefined label key: "undefined_key" (not in label schema)`,
		},
		{
			name: "dedupe label keys without label schema",
			mutate: func(payload *RiskTemplatePayload) {
				payload.DedupeLabelKeys = []string{"some_key"}
			},
			message: "dedupeLabelKeys requires a non-empty labelSchema",
		},
		{
			name: "dedupe label key not in label schema",
			mutate: func(payload *RiskTemplatePayload) {
				payload.LabelSchema = []RiskTemplateLabelSchemaFieldInput{
					{Key: "defined_key"},
				}
				payload.DedupeLabelKeys = []string{"undefined_key"}
			},
			message: `dedupeLabelKeys key "undefined_key" is not defined in labelSchema`,
		},
		{
			name: "duplicate label schema keys",
			mutate: func(payload *RiskTemplatePayload) {
				payload.LabelSchema = []RiskTemplateLabelSchemaFieldInput{
					{Key: "dup_key"},
					{Key: "dup_key"},
				}
			},
			message: `labelSchema has duplicate key "dup_key"`,
		},
		{
			name: "duplicate dedupe label keys",
			mutate: func(payload *RiskTemplatePayload) {
				payload.LabelSchema = []RiskTemplateLabelSchemaFieldInput{
					{Key: "key_a"},
				}
				payload.DedupeLabelKeys = []string{"key_a", "key_a"}
			},
			message: `dedupeLabelKeys has duplicate key "key_a"`,
		},
		{
			name: "label schema key over max length",
			mutate: func(payload *RiskTemplatePayload) {
				payload.LabelSchema = []RiskTemplateLabelSchemaFieldInput{
					{Key: strings.Repeat("k", maxRiskTemplateFieldLength+1)},
				}
			},
			message: "labelSchema[0].key must be at most 1000 characters",
		},
		{
			name: "label schema description over max length",
			mutate: func(payload *RiskTemplatePayload) {
				description := strings.Repeat("d", maxRiskTemplateFieldLength+1)
				payload.LabelSchema = []RiskTemplateLabelSchemaFieldInput{
					{Key: "defined_key", Description: &description},
				}
			},
			message: "labelSchema[0].description must be at most 1000 characters",
		},
		{
			name: "template-capable field over max length",
			mutate: func(payload *RiskTemplatePayload) {
				payload.Title = strings.Repeat("t", maxRiskTemplateFieldLength+1)
				payload.LabelSchema = []RiskTemplateLabelSchemaFieldInput{
					{Key: "defined_key"},
				}
			},
			message: "title must be at most 1000 characters",
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

func TestRiskTemplateService_BatchUpsertWithTemplateCapableFields(t *testing.T) {
	db := newRiskTemplateTestDB(t)
	svc := NewRiskTemplateService(db)

	pluginID := "batch-tmpl-plugin"
	policy := "compliance_framework.batch_tmpl_test"

	titleTmpl := "CVE {{.cve_id}} in {{.repo}}"
	stmtTmpl := "Severity: {{.severity}}"
	id1 := uuid.New()

	// Round 1: create with template-capable fields
	result, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{
			ID:        id1,
			Name:      "Templated batch",
			Title:     titleTmpl,
			Statement: stmtTmpl,
			LabelSchema: []RiskTemplateLabelSchemaFieldInput{
				{Key: "cve_id"},
				{Key: "repo"},
				{Key: "severity"},
			},
			DedupeLabelKeys: []string{"cve_id"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.Created, 1)
	require.Len(t, result.Created[0].LabelSchema, 3)
	require.Equal(t, titleTmpl, result.Created[0].Title)
	require.Len(t, result.Created[0].DedupeLabelKeys, 1)

	// Round 2: same payload — should be unchanged
	result2, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{
			ID:        id1,
			Name:      "Templated batch",
			Title:     titleTmpl,
			Statement: stmtTmpl,
			LabelSchema: []RiskTemplateLabelSchemaFieldInput{
				{Key: "cve_id"},
				{Key: "repo"},
				{Key: "severity"},
			},
			DedupeLabelKeys: []string{"cve_id"},
		},
	})
	require.NoError(t, err)
	require.Empty(t, result2.Created)
	require.Empty(t, result2.Updated)
	require.Empty(t, result2.Deleted)
	require.Len(t, result2.Unchanged, 1)
	require.Equal(t, id1, result2.Unchanged[0])

	// Round 3: change template-capable field — should be updated
	newTitleTmpl := "Issue {{.cve_id}}"
	result3, err := svc.BatchUpsert(pluginID, policy, []BatchRiskTemplateItem{
		{
			ID:        id1,
			Name:      "Templated batch",
			Title:     newTitleTmpl,
			Statement: stmtTmpl,
			LabelSchema: []RiskTemplateLabelSchemaFieldInput{
				{Key: "cve_id"},
				{Key: "repo"},
				{Key: "severity"},
			},
			DedupeLabelKeys: []string{"cve_id"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result3.Updated, 1)
	require.Equal(t, newTitleTmpl, result3.Updated[0].Title)
}
