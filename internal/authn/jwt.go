package authn

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenKindUser              = "user"
	TokenKindAgent             = "agent"
	TokenKindEvidenceSignature = "evidence_signature"
)

type UserClaims struct {
	jwt.RegisteredClaims
	TokenKind  string `json:"token_kind"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
}

type PasswordResetClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
}

type AgentClaims struct {
	jwt.RegisteredClaims
	TokenKind    string `json:"token_kind"`
	AgentID      string `json:"agent_id"`
	CredentialID string `json:"credential_id"`
	AuthMethod   string `json:"auth_method"`
}

func GenerateJWTToken(user *relational.User, privateKey *rsa.PrivateKey) (*string, error) {
	now := time.Now()
	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "compliance-framework",
			Subject:   user.Email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
		},
		TokenKind:  TokenKindUser,
		GivenName:  user.FirstName,
		FamilyName: user.LastName,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

func GenerateAgentJWTToken(agent *relational.Agent, key *relational.AgentServiceAccountKey, privateKey *rsa.PrivateKey) (*string, error) {
	now := time.Now()
	claims := AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "compliance-framework",
			Subject:   key.ClientID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
		},
		TokenKind:    TokenKindAgent,
		AgentID:      agent.ID.String(),
		CredentialID: key.ID.String(),
		AuthMethod:   relational.AgentAuthMethodServiceAccount,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

func GeneratePasswordResetToken(email string, privateKey *rsa.PrivateKey) (*string, error) {
	now := time.Now()
	claims := PasswordResetClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "compliance-framework",
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)), // 15 minutes expiry
			NotBefore: jwt.NewNumericDate(now),
		},
		Email: email,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

func VerifyJWTToken(tokenString string, publicKey *rsa.PublicKey) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		if claims.TokenKind != TokenKindUser {
			return nil, errors.New("unexpected token kind")
		}
		return claims, nil
	}
	return nil, jwt.ErrTokenMalformed
}

func VerifyAgentJWTToken(tokenString string, publicKey *rsa.PublicKey) (*AgentClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AgentClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*AgentClaims); ok && token.Valid {
		if claims.TokenKind != TokenKindAgent {
			return nil, errors.New("unexpected token kind")
		}
		return claims, nil
	}
	return nil, jwt.ErrTokenMalformed
}

func VerifyPasswordResetToken(tokenString string, publicKey *rsa.PublicKey) (*PasswordResetClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &PasswordResetClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*PasswordResetClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrTokenMalformed
}
