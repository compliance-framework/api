package authn

import (
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestUserAndAgentTokensAreSeparated(t *testing.T) {
	privateKey, publicKey, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	user := &relational.User{
		Email:     "dummy@example.com",
		FirstName: "Dummy",
		LastName:  "User",
	}
	userToken, err := GenerateJWTToken(user, privateKey)
	require.NoError(t, err)

	agentID := uuid.New()
	keyID := uuid.New()
	agent := &relational.Agent{UUIDModel: relational.UUIDModel{ID: &agentID}}
	key := &relational.AgentServiceAccountKey{
		UUIDModel: relational.UUIDModel{ID: &keyID},
		ClientID:  "client-id",
	}
	agentToken, err := GenerateAgentJWTToken(agent, key, privateKey)
	require.NoError(t, err)

	userClaims, err := VerifyJWTToken(*userToken, publicKey)
	require.NoError(t, err)
	require.Equal(t, TokenKindUser, userClaims.TokenKind)

	_, err = VerifyJWTToken(*agentToken, publicKey)
	require.Error(t, err)

	agentClaims, err := VerifyAgentJWTToken(*agentToken, publicKey)
	require.NoError(t, err)
	require.Equal(t, TokenKindAgent, agentClaims.TokenKind)

	_, err = VerifyAgentJWTToken(*userToken, publicKey)
	require.Error(t, err)
}
