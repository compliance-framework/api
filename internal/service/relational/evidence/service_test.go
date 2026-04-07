package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/templates"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newEvidenceServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.Evidence{},
		&relational.Labels{},
		&relational.BackMatter{},
		&relational.BackMatterResource{},
		&relational.Activity{},
		&relational.Step{},
		&relational.SystemComponent{},
		&relational.InventoryItem{},
		&relational.AssessmentSubject{},
	))
	return db
}

func TestEvidenceService_Create_WithLabels(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil, nil, nil)

	evidenceID := internal.Pointer(uuid.New())
	streamUUID := uuid.New()
	now := time.Now().UTC()

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUIDModel: relational.UUIDModel{ID: evidenceID},
			UUID:      streamUUID,
			Title:     "SSH password auth enabled",
			Start:     now.Add(-time.Hour),
			End:       now.Add(-time.Minute),
			Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied", Reason: "fail"}),
		},
		Labels: []relational.Labels{
			{Name: "provider", Value: "aws"},
			{Name: "service", Value: "ec2"},
		},
	}

	result, err := svc.Create(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, evidenceID, result.ID)
	require.Equal(t, streamUUID, result.UUID)

	var count int64
	require.NoError(t, db.Model(&relational.Evidence{}).Count(&count).Error)
	require.Equal(t, int64(1), count)

	var labelCount int64
	require.NoError(t, db.Model(&relational.Labels{}).Count(&labelCount).Error)
	require.Equal(t, int64(2), labelCount)

	var linkCount int64
	require.NoError(t, db.Table("evidence_labels").Count(&linkCount).Error)
	require.Equal(t, int64(2), linkCount)
}

func TestEvidenceService_Create_AutoSetsExpiry(t *testing.T) {
	db := newEvidenceServiceTestDB(t)

	// cfg with 3 months expiry
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	svc := NewEvidenceService(db, logger.Sugar(), &config.Config{EvidenceDefaultExpiryMonths: 3}, nil)

	now := time.Now().UTC()
	end := now.Add(-time.Minute)

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:  uuid.New(),
			Title: "test",
			Start: now.Add(-time.Hour),
			End:   end,
		},
	}

	result, err := svc.Create(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, result.Expires)
	expected := end.AddDate(0, 3, 0)
	require.WithinDuration(t, expected, *result.Expires, time.Second)
}

func TestEvidenceService_Create_PreservesExplicitExpiry(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	svc := NewEvidenceService(db, logger.Sugar(), &config.Config{EvidenceDefaultExpiryMonths: 3}, nil)

	now := time.Now().UTC()
	explicitExpiry := now.Add(90 * 24 * time.Hour)

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:    uuid.New(),
			Title:   "test",
			Start:   now.Add(-time.Hour),
			End:     now.Add(-time.Minute),
			Expires: &explicitExpiry,
		},
	}

	result, err := svc.Create(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, result.Expires)
	require.WithinDuration(t, explicitExpiry, *result.Expires, time.Second)
}

func TestSigningService_CanonicalHashStableAcrossReorderedCollections(t *testing.T) {
	privateKey, _, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	signingSvc := NewSigningService(privateKey)
	signingSvc.now = func() time.Time {
		return time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC)
	}

	now := time.Date(2026, 4, 7, 11, 30, 0, 0, time.UTC)
	status := datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied})
	paramsA := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:   uuid.MustParse("f700fda2-e4b9-4f0c-b673-bcf9bb6dbfe8"),
			Title:  "signed-evidence",
			Start:  now.Add(-time.Hour),
			End:    now,
			Status: status,
			Props: datatypes.NewJSONSlice([]relational.Prop{
				{Name: "z", Value: "9"},
				{Name: "a", Value: "1"},
			}),
		},
		Activities: []relational.Activity{
			{UUIDModel: relational.UUIDModel{ID: internal.Pointer(uuid.MustParse("45b8382d-127b-47cc-a2ef-053fa5a6b15f"))}, Title: internal.Pointer("B"), Description: "second"},
			{UUIDModel: relational.UUIDModel{ID: internal.Pointer(uuid.MustParse("21569f93-ca01-428c-b877-d9c7e14d7bad"))}, Title: internal.Pointer("A"), Description: "first"},
		},
		Labels: []relational.Labels{
			{Name: "env", Value: "prod"},
			{Name: "service", Value: "api"},
		},
	}
	paramsB := paramsA
	paramsB.Activities = []relational.Activity{paramsA.Activities[1], paramsA.Activities[0]}
	paramsB.Labels = []relational.Labels{paramsA.Labels[1], paramsA.Labels[0]}
	paramsB.Evidence.Props = datatypes.NewJSONSlice([]relational.Prop{
		{Name: "a", Value: "1"},
		{Name: "z", Value: "9"},
	})

	signer := NewUserSignerContextFromClaims(&authn.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "signer@example.com",
		},
		GivenName:  "Signer",
		FamilyName: "User",
	})

	sigA, err := signingSvc.SignEvidence(paramsA, signer)
	require.NoError(t, err)
	sigB, err := signingSvc.SignEvidence(paramsB, signer)
	require.NoError(t, err)
	require.NotNil(t, sigA)
	require.NotNil(t, sigB)
	require.Equal(t, sigA.Data().ContentHash.Value, sigB.Data().ContentHash.Value)
}

func TestSigningService_ContentHashChangesWhenEvidenceChanges(t *testing.T) {
	privateKey, _, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	signingSvc := NewSigningService(privateKey)
	now := time.Date(2026, 4, 7, 11, 30, 0, 0, time.UTC)
	signer := NewUserSignerContextFromClaims(&authn.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "signer@example.com"},
	})

	base := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:  uuid.MustParse("f700fda2-e4b9-4f0c-b673-bcf9bb6dbfe8"),
			Title: "signed-evidence",
			Start: now.Add(-time.Hour),
			End:   now,
			Props: datatypes.NewJSONSlice([]relational.Prop{
				{Name: "check", Value: "baseline"},
			}),
			BackMatter: &relational.BackMatter{
				Resources: []relational.BackMatterResource{
					{
						ID: uuid.MustParse("3d31fa64-edb4-4218-b242-bf03e3e6db77"),
						Base64: internal.Pointer(datatypes.NewJSONType(relational.Base64{
							Filename:  "evidence.txt",
							MediaType: "text/plain",
							Value:     "YmFzZQ==",
						})),
					},
				},
			},
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		},
		Labels: []relational.Labels{{Name: "env", Value: "prod"}},
	}

	baseSig, err := signingSvc.SignEvidence(base, signer)
	require.NoError(t, err)

	withAttachmentChange := base
	withAttachmentChange.Evidence.BackMatter = &relational.BackMatter{
		Resources: []relational.BackMatterResource{
			{
				ID: uuid.MustParse("3d31fa64-edb4-4218-b242-bf03e3e6db77"),
				Base64: internal.Pointer(datatypes.NewJSONType(relational.Base64{
					Filename:  "evidence.txt",
					MediaType: "text/plain",
					Value:     "Y2hhbmdlZA==",
				})),
			},
		},
	}
	attachmentSig, err := signingSvc.SignEvidence(withAttachmentChange, signer)
	require.NoError(t, err)
	require.NotEqual(t, baseSig.Data().ContentHash.Value, attachmentSig.Data().ContentHash.Value)

	withStatusChange := base
	withStatusChange.Evidence.Status = datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusNotSatisfied})
	statusSig, err := signingSvc.SignEvidence(withStatusChange, signer)
	require.NoError(t, err)
	require.NotEqual(t, baseSig.Data().ContentHash.Value, statusSig.Data().ContentHash.Value)

	withPropChange := base
	withPropChange.Evidence.Props = datatypes.NewJSONSlice([]relational.Prop{{Name: "check", Value: "different"}})
	propSig, err := signingSvc.SignEvidence(withPropChange, signer)
	require.NoError(t, err)
	require.NotEqual(t, baseSig.Data().ContentHash.Value, propSig.Data().ContentHash.Value)

	withLabelChange := base
	withLabelChange.Labels = []relational.Labels{{Name: "env", Value: "staging"}}
	labelSig, err := signingSvc.SignEvidence(withLabelChange, signer)
	require.NoError(t, err)
	require.NotEqual(t, baseSig.Data().ContentHash.Value, labelSig.Data().ContentHash.Value)
}

func TestEvidenceService_Create_SignsWithUserAndAgentContexts(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	privateKey, _, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	svc := NewEvidenceService(db, logger.Sugar(), &config.Config{JWTPrivateKey: privateKey}, nil)
	now := time.Now().UTC()

	userResult, err := svc.Create(context.Background(), CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:   uuid.New(),
			Title:  "signed-user",
			Start:  now.Add(-time.Hour),
			End:    now,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		},
		Signer: NewUserSignerContextFromClaims(&authn.UserClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "user@example.com"},
			GivenName:        "User",
			FamilyName:       "Signer",
		}),
	})
	require.NoError(t, err)
	require.NotNil(t, userResult.Signature)
	require.Equal(t, "user@example.com", userResult.Signature.Data().Claims.Subject)
	require.Equal(t, authn.TokenKindUser, userResult.Signature.Data().Signer.Type)

	agentID := uuid.New()
	credentialID := uuid.New()
	agentResult, err := svc.Create(context.Background(), CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:   uuid.New(),
			Title:  "signed-agent",
			Start:  now.Add(-time.Hour),
			End:    now,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		},
		Signer: NewAgentSignerContext(
			&authn.AgentClaims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "client-id"},
				AgentID:          agentID.String(),
				CredentialID:     credentialID.String(),
				AuthMethod:       relational.AgentAuthMethodServiceAccount,
			},
			&relational.Agent{UUIDModel: relational.UUIDModel{ID: &agentID}, Name: "agent-one"},
			&relational.AgentServiceAccountKey{UUIDModel: relational.UUIDModel{ID: &credentialID}},
		),
	})
	require.NoError(t, err)
	require.NotNil(t, agentResult.Signature)
	require.Equal(t, authn.TokenKindAgent, agentResult.Signature.Data().Signer.Type)
	require.Equal(t, credentialID.String(), agentResult.Signature.Data().Signer.CredentialID)
	require.Equal(t, relational.AgentAuthMethodServiceAccount, agentResult.Signature.Data().Claims.AuthMethod)
}

func TestEvidenceService_Create_LeavesSignatureNilWithoutSigner(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	privateKey, _, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	svc := NewEvidenceService(db, logger.Sugar(), &config.Config{JWTPrivateKey: privateKey}, nil)
	now := time.Now().UTC()

	result, err := svc.Create(context.Background(), CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:   uuid.New(),
			Title:  "unsigned",
			Start:  now.Add(-time.Hour),
			End:    now,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		},
	})
	require.NoError(t, err)
	require.Nil(t, result.Signature)
}

func TestSigningService_AllowsSubjectsWithNilNestedRemarks(t *testing.T) {
	privateKey, _, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	signingSvc := NewSigningService(privateKey)
	now := time.Now().UTC()
	signer := NewUserSignerContextFromClaims(&authn.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "user@example.com"},
	})

	signature, err := signingSvc.SignEvidence(CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:   uuid.New(),
			Title:  "subject-nil-remarks",
			Start:  now.Add(-time.Hour),
			End:    now,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		},
		Subjects: []relational.AssessmentSubject{
			{
				Type: "inventory-item",
				IncludeSubjects: []relational.SelectSubjectById{
					{
						SubjectUUID: uuid.New(),
					},
				},
			},
		},
	}, signer)
	require.NoError(t, err)
	require.NotNil(t, signature)
}

func TestEvidenceService_Create_DuplicateLabelsAreIdempotent(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil, nil, nil)

	label := relational.Labels{Name: "env", Value: "prod"}

	// First evidence
	_, err := svc.Create(context.Background(), CreateEvidenceParams{
		Evidence: relational.Evidence{UUID: uuid.New(), Title: "e1", Start: time.Now().Add(-time.Hour), End: time.Now()},
		Labels:   []relational.Labels{label},
	})
	require.NoError(t, err)

	// Second evidence with same label
	_, err = svc.Create(context.Background(), CreateEvidenceParams{
		Evidence: relational.Evidence{UUID: uuid.New(), Title: "e2", Start: time.Now().Add(-time.Hour), End: time.Now()},
		Labels:   []relational.Labels{label},
	})
	require.NoError(t, err)

	var labelCount int64
	require.NoError(t, db.Model(&relational.Labels{}).Count(&labelCount).Error)
	require.Equal(t, int64(1), labelCount)

	var evidenceCount int64
	require.NoError(t, db.Model(&relational.Evidence{}).Count(&evidenceCount).Error)
	require.Equal(t, int64(2), evidenceCount)
}

func TestEvidenceService_GetByID(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil, nil, nil)

	id := internal.Pointer(uuid.New())
	now := time.Now().UTC()

	evidence := relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: id},
		UUID:      uuid.New(),
		Title:     "get-by-id test",
		Start:     now.Add(-time.Hour),
		End:       now.Add(-time.Minute),
	}
	require.NoError(t, db.Create(&evidence).Error)

	result, err := svc.GetByID(*id)
	require.NoError(t, err)
	require.Equal(t, id, result.ID)
	require.Equal(t, "get-by-id test", result.Title)
}

func TestEvidenceService_GetByID_NotFound(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil, nil, nil)

	_, err := svc.GetByID(uuid.New())
	require.Error(t, err)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestEvidenceService_GetHistory(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil, nil, nil)

	streamUUID := uuid.New()
	now := time.Now().UTC()

	evidences := []relational.Evidence{
		{
			UUID:  streamUUID,
			Title: "newest",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "older",
			Start: now.Add(-12 * time.Minute),
			End:   now.Add(-10 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "oldest",
			Start: now.Add(-22 * time.Minute),
			End:   now.Add(-20 * time.Minute),
		},
	}
	require.NoError(t, db.Create(&evidences).Error)

	results, err := svc.GetHistory(streamUUID)
	require.NoError(t, err)
	require.Len(t, results, 3)
	// Ordered by end DESC
	require.Equal(t, "newest", results[0].Title)
	require.Equal(t, "older", results[1].Title)
	require.Equal(t, "oldest", results[2].Title)
}

func TestEvidenceService_GetHistory_EmptyForUnknownStream(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil, nil, nil)

	results, err := svc.GetHistory(uuid.New())
	require.NoError(t, err)
	require.Empty(t, results)
}

// mockCDResolver is a mock implementation of ComponentDefinitionResolver for testing.
type mockCDResolver struct {
	definedComponentIDs []uuid.UUID
	systemComponents    []relational.SystemComponent
}

func (m *mockCDResolver) ResolveOrUpsertComponentDefinition(_ templates.ResolveOrUpsertComponentDefinitionInput) (*templates.ResolveOrUpsertComponentDefinitionResult, error) {
	return &templates.ResolveOrUpsertComponentDefinitionResult{
		DefinedComponentIDs: m.definedComponentIDs,
	}, nil
}

func (m *mockCDResolver) FindSystemComponentsByDefinedComponentIDs(_ []uuid.UUID) ([]relational.SystemComponent, error) {
	return m.systemComponents, nil
}

func TestEvidenceService_Create_MergesResolverSystemComponents(t *testing.T) {
	db := newEvidenceServiceTestDB(t)

	// Create a pre-existing SystemComponent in the DB.
	scID := internal.Pointer(uuid.New())
	sc := relational.SystemComponent{
		UUIDModel:   relational.UUIDModel{ID: scID},
		Type:        "component",
		Title:       "resolved component",
		Description: "auto-discovered",
	}
	require.NoError(t, db.Create(&sc).Error)

	resolver := &mockCDResolver{
		definedComponentIDs: []uuid.UUID{uuid.New()},
		systemComponents:    []relational.SystemComponent{sc},
	}

	svc := NewEvidenceService(db, nil, nil, nil, WithComponentDefinitionResolver(resolver))

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:  uuid.New(),
			Title: "evidence with resolver",
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		Labels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
		},
	}

	result, err := svc.Create(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify the evidence has the resolver-discovered component associated.
	var linkCount int64
	require.NoError(t, db.Table("evidence_components").Where("evidence_id = ?", *result.ID).Count(&linkCount).Error)
	require.Equal(t, int64(1), linkCount)
}

func TestEvidenceService_Create_DeduplicatesResolverSystemComponents(t *testing.T) {
	db := newEvidenceServiceTestDB(t)

	scID := internal.Pointer(uuid.New())
	sc := relational.SystemComponent{
		UUIDModel:   relational.UUIDModel{ID: scID},
		Type:        "component",
		Title:       "shared component",
		Description: "both explicit and resolved",
	}
	require.NoError(t, db.Create(&sc).Error)

	resolver := &mockCDResolver{
		definedComponentIDs: []uuid.UUID{uuid.New()},
		systemComponents:    []relational.SystemComponent{sc},
	}

	svc := NewEvidenceService(db, nil, nil, nil, WithComponentDefinitionResolver(resolver))

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:  uuid.New(),
			Title: "evidence with dedup",
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		Components: []relational.SystemComponent{sc}, // Already passed explicitly
		Labels: []relational.Labels{
			{Name: "_plugin", Value: "github"},
			{Name: "asset_id", Value: "srv-123"},
		},
	}

	result, err := svc.Create(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should only have 1 link, not 2 (dedup).
	var linkCount int64
	require.NoError(t, db.Table("evidence_components").Where("evidence_id = ?", *result.ID).Count(&linkCount).Error)
	require.Equal(t, int64(1), linkCount)
}
