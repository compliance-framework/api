package authn

import (
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/golang-jwt/jwt/v5"
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

func TestGenerateJWTToken_IncludesUserUUID(t *testing.T) {
	privateKey, publicKey, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	userID := uuid.New()
	user := &relational.User{
		UUIDModel: relational.UUIDModel{ID: &userID},
		Email:     "owner@example.com",
	}
	token, err := GenerateJWTToken(user, privateKey)
	require.NoError(t, err)

	claims, err := VerifyJWTToken(*token, publicKey)
	require.NoError(t, err)
	require.Equal(t, user.Email, claims.Subject, "subject stays the email")
	require.Equal(t, userID.String(), claims.UserUUID, "user_uuid claim carries users.ID")
}

func TestGenerateJWTToken_NilUserIDOmitsUUID(t *testing.T) {
	privateKey, publicKey, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	// A user with no ID set must not panic and must simply omit the claim.
	token, err := GenerateJWTToken(&relational.User{Email: "noid@example.com"}, privateKey)
	require.NoError(t, err)

	claims, err := VerifyJWTToken(*token, publicKey)
	require.NoError(t, err)
	require.Empty(t, claims.UserUUID)
}

func TestVerifyJWTToken_RejectsEvidenceSignatureToken(t *testing.T) {
	privateKey, publicKey, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"token_kind": TokenKindEvidenceSignature,
		"version":    "v1",
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	_, err = VerifyJWTToken(tokenString, publicKey)
	require.Error(t, err)
}
