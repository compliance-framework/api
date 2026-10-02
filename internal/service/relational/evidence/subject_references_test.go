package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/templates"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func ccfProp(name, value string) relational.Prop {
	return relational.Prop{Ns: relational.CCFOSCALNamespace, Name: name, Value: value}
}

func orgSubject() templates.ResolvedSubject {
	return templates.ResolvedSubject{
		DefinedComponentID: uuid.New(),
		TemplateID:         uuid.New(),
		TemplateName:       "github-organization",
		DisplayPriority:    3,
		Type:               "component",
		Title:              "GitHub Organization: acme",
		Props:              []relational.Prop{ccfProp("identity", "acme")},
		Links:              []relational.Link{{Href: "https://github.com/acme", Rel: "canonical"}},
	}
}

func subjectTestParams() CreateEvidenceParams {
	now := time.Now().UTC()
	return CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:   uuid.New(),
			Title:  "All teams use closed visibility",
			Start:  now.Add(-time.Hour),
			End:    now.Add(-time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		},
		Labels: []relational.Labels{
			{Name: "_plugin", Value: "github-settings"},
			{Name: "organization", Value: "acme"},
		},
	}
}

func legacySubject(identifierUUID uuid.UUID) relational.AssessmentSubject {
	return relational.AssessmentSubject{
		Type:            "Component",
		IncludeSubjects: []relational.SelectSubjectById{{SubjectUUID: identifierUUID}},
		Props:           datatypes.NewJSONSlice([]relational.Prop{{Name: "repo", Value: "api"}}),
		Remarks:         internal.Pointer(""),
	}
}

func TestEvidenceService_Create_StoresTemplateDerivedSubjects(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	subject := orgSubject()
	svc := NewEvidenceService(db, nil, nil, nil, WithComponentDefinitionResolver(&mockCDResolver{
		definedComponentIDs: []uuid.UUID{subject.DefinedComponentID},
		subjects:            []templates.ResolvedSubject{subject},
	}))

	created, err := svc.Create(context.Background(), subjectTestParams())
	require.NoError(t, err)
	require.Len(t, created.SubjectReferences, 1, "the created evidence carries its subjects")

	stored, err := svc.GetByID(*created.ID)
	require.NoError(t, err)
	require.Len(t, stored.SubjectReferences, 1)

	ref := stored.SubjectReferences[0]
	require.Equal(t, *created.ID, ref.EvidenceID)
	require.Equal(t, subject.DefinedComponentID, ref.SubjectUUID)
	require.Equal(t, "component", ref.Type)
	require.Equal(t, "GitHub Organization: acme", ref.Title)
	require.Equal(t, relational.EvidenceSubjectSourceTemplate, ref.Source)
	require.Equal(t, subject.TemplateID, *ref.TemplateID)
	require.Equal(t, 3, ref.Priority)
	require.Nil(t, ref.Group)
	require.Equal(t, []relational.Prop{
		ccfProp("subject-source", "template"),
		ccfProp("subject-template", "github-organization"),
		ccfProp("display-priority", "3"),
	}, []relational.Prop(ref.Props))
	require.Equal(t, subject.Links, []relational.Link(ref.Links))
}

func TestEvidenceService_Create_StoresLegacySubjectsAsLegacy(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil, nil, nil)

	identifierUUID := uuid.New()
	params := subjectTestParams()
	params.Subjects = []relational.AssessmentSubject{legacySubject(identifierUUID)}

	created, err := svc.Create(context.Background(), params)
	require.NoError(t, err)

	stored, err := svc.GetByID(*created.ID)
	require.NoError(t, err)
	require.Len(t, stored.Subjects, 1, "the legacy assessment subject is still stored as before")
	require.Len(t, stored.SubjectReferences, 1)

	ref := stored.SubjectReferences[0]
	require.Equal(t, identifierUUID, ref.SubjectUUID)
	require.Equal(t, "Component", ref.Type)
	require.Empty(t, ref.Title)
	require.Equal(t, relational.EvidenceSubjectSourceLegacy, ref.Source)
	require.Nil(t, ref.TemplateID)
	require.Nil(t, ref.Remarks)
	require.Equal(t, []relational.Prop{
		{Name: "repo", Value: "api"},
		ccfProp("subject-source", "legacy"),
	}, []relational.Prop(ref.Props))
}

func TestEvidenceService_Create_AppliesRequireSubjectToAgentEvidence(t *testing.T) {
	userSigner := NewUserSignerContextFromClaims(&authn.UserClaims{})
	agentSigner := NewAgentSignerContext(&authn.AgentClaims{}, nil, nil)

	testCases := []struct {
		name        string
		mode        config.EvidenceRequireSubjectMode
		signer      *SignerContext
		origin      EvidenceOrigin
		resolver    *mockCDResolver
		legacy      bool
		wantErr     bool
		wantRefsLen int
	}{
		{name: "off accepts unattributed agent evidence", mode: config.EvidenceRequireSubjectOff},
		{name: "warn accepts unattributed agent evidence", mode: config.EvidenceRequireSubjectWarn},
		{name: "enforce rejects unattributed agent evidence", mode: config.EvidenceRequireSubjectEnforce, wantErr: true},
		{name: "enforce rejects agent-signed evidence without a subject", mode: config.EvidenceRequireSubjectEnforce, signer: agentSigner, wantErr: true},
		{name: "enforce does not count legacy subjects", mode: config.EvidenceRequireSubjectEnforce, legacy: true, wantErr: true},
		{
			name:        "enforce accepts evidence with a template-derived subject",
			mode:        config.EvidenceRequireSubjectEnforce,
			resolver:    &mockCDResolver{subjects: []templates.ResolvedSubject{orgSubject()}},
			wantRefsLen: 1,
		},
		{
			name:     "enforce treats a resolver error as no subject",
			mode:     config.EvidenceRequireSubjectEnforce,
			resolver: &mockCDResolver{err: errors.New("resolver unavailable")},
			wantErr:  true,
		},
		{name: "enforce does not apply to user evidence", mode: config.EvidenceRequireSubjectEnforce, signer: userSigner},
		{name: "enforce does not apply to workflow evidence", mode: config.EvidenceRequireSubjectEnforce, signer: userSigner, origin: OriginWorkflow},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newEvidenceServiceTestDB(t)
			logger, err := zap.NewDevelopment()
			require.NoError(t, err)
			opts := []EvidenceServiceOption{}
			if tc.resolver != nil {
				opts = append(opts, WithComponentDefinitionResolver(tc.resolver))
			}
			svc := NewEvidenceService(db, logger.Sugar(), &config.Config{
				EvidenceSubjects: &config.EvidenceSubjectConfig{RequireSubject: tc.mode},
			}, nil, opts...)

			params := subjectTestParams()
			params.Signer = tc.signer
			params.Origin = tc.origin
			wantRefsLen := tc.wantRefsLen
			if tc.legacy {
				params.Subjects = []relational.AssessmentSubject{legacySubject(uuid.New())}
				wantRefsLen++
			}

			created, err := svc.Create(context.Background(), params)

			var count int64
			require.NoError(t, db.Model(&relational.Evidence{}).Count(&count).Error)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrSubjectRequired)
				require.Zero(t, count, "rejected evidence is not saved")
				return
			}
			require.NoError(t, err)
			require.Equal(t, int64(1), count)
			require.Len(t, created.SubjectReferences, wantRefsLen)
		})
	}
}

func TestEvidenceService_Create_SignsSubjectReferences(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	privateKey, publicKey, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)
	svc := NewEvidenceService(db, logger.Sugar(), &config.Config{
		JWTPrivateKey: privateKey,
		JWTPublicKey:  publicKey,
	}, nil, WithComponentDefinitionResolver(&mockCDResolver{
		subjects: []templates.ResolvedSubject{orgSubject()},
	}))

	signedAt := time.Now().UTC()
	created := createSignedEvidenceForVerification(t, svc, subjectTestParams(), signedAt, newVerificationSigner(
		"signer@example.com",
		signedAt.Add(-time.Hour),
		signedAt.Add(-time.Hour),
		signedAt.Add(time.Hour),
	))

	result, err := svc.VerifyByID(*created.ID)
	require.NoError(t, err)
	require.True(t, result.IsValid, result.Errors)

	require.NoError(t, db.Model(&relational.EvidenceSubjectReference{}).
		Where("evidence_id = ?", *created.ID).
		Update("title", "GitHub Organization: someone-else").Error)

	result, err = svc.VerifyByID(*created.ID)
	require.NoError(t, err)
	require.False(t, result.IsValid, "changing a subject reference breaks the signature")
	require.False(t, result.Checks.HashMatch)
}

func TestEvidenceService_Create_AppliesManualRequireSubjectToUserEvidence(t *testing.T) {
	userSigner := NewUserSignerContextFromClaims(&authn.UserClaims{})
	agentSigner := NewAgentSignerContext(&authn.AgentClaims{}, nil, nil)

	testCases := []struct {
		name     string
		required bool
		signer   *SignerContext
		origin   EvidenceOrigin
		resolver *mockCDResolver
		legacy   bool
		wantErr  bool
	}{
		{name: "not required accepts user evidence without a subject", signer: userSigner},
		{name: "required rejects user evidence without a subject", required: true, signer: userSigner, wantErr: true},
		{name: "required does not count legacy subjects", required: true, signer: userSigner, legacy: true, wantErr: true},
		{
			name:     "required accepts user evidence with a template-derived subject",
			required: true,
			signer:   userSigner,
			resolver: &mockCDResolver{subjects: []templates.ResolvedSubject{orgSubject()}},
		},
		{name: "required does not apply to workflow evidence", required: true, signer: userSigner, origin: OriginWorkflow},
		{name: "required does not apply to agent evidence", required: true, signer: agentSigner},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newEvidenceServiceTestDB(t)
			opts := []EvidenceServiceOption{}
			if tc.resolver != nil {
				opts = append(opts, WithComponentDefinitionResolver(tc.resolver))
			}
			svc := NewEvidenceService(db, nil, &config.Config{
				EvidenceSubjects: &config.EvidenceSubjectConfig{ManualRequireSubject: tc.required},
			}, nil, opts...)

			params := subjectTestParams()
			params.Signer = tc.signer
			params.Origin = tc.origin
			if tc.legacy {
				params.Subjects = []relational.AssessmentSubject{legacySubject(uuid.New())}
			}

			_, err := svc.Create(context.Background(), params)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrSubjectRequired)
				require.Contains(t, err.Error(), "subjects[].subject-uuid")
				return
			}
			require.NoError(t, err)
		})
	}
}
