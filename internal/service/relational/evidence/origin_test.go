package evidence

import (
	"testing"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestOriginFromSigner(t *testing.T) {
	require.Equal(t, OriginUser, OriginFromSigner(NewUserSignerContextFromClaims(&authn.UserClaims{})))
	require.Equal(t, OriginAgent, OriginFromSigner(NewAgentSignerContext(&authn.AgentClaims{}, nil, nil)))
	require.Equal(t, OriginAgent, OriginFromSigner(nil), "anonymous public ingest counts as agent")
}

func TestCreateEvidenceParamsEffectiveOrigin(t *testing.T) {
	userSigner := NewUserSignerContextFromClaims(&authn.UserClaims{})

	require.Equal(t, OriginUser, CreateEvidenceParams{Signer: userSigner}.EffectiveOrigin())
	require.Equal(t, OriginWorkflow, CreateEvidenceParams{Signer: userSigner, Origin: OriginWorkflow}.EffectiveOrigin(),
		"an origin set by the creation path wins over the signer")
}

func TestEvidenceServiceManualEvidenceRequiresSubject(t *testing.T) {
	var nilService *EvidenceService
	require.False(t, nilService.ManualEvidenceRequiresSubject())
	require.False(t, NewEvidenceService(nil, nil, &config.Config{}, nil).ManualEvidenceRequiresSubject())
	require.False(t, NewEvidenceService(nil, nil, &config.Config{
		EvidenceSubjects: &config.EvidenceSubjectConfig{ManualRequireSubject: false},
	}, nil).ManualEvidenceRequiresSubject())
	require.True(t, NewEvidenceService(nil, nil, &config.Config{
		EvidenceSubjects: &config.EvidenceSubjectConfig{ManualRequireSubject: true},
	}, nil).ManualEvidenceRequiresSubject())
}
