package middleware

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type AgentAuthContext struct {
	Claims *authn.AgentClaims
	Agent  *relational.Agent
	Key    *relational.AgentServiceAccountKey
}

func AgentJWTMiddleware(db *gorm.DB, publicKey *rsa.PublicKey) echo.MiddlewareFunc {
	return AgentJWTOrPublicMiddleware(db, publicKey, false)
}

func AgentJWTOrPublicMiddleware(db *gorm.DB, publicKey *rsa.PublicKey, allowPublic bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == http.MethodOptions {
				return next(c)
			}

			authHeader := c.Request().Header.Get(echo.HeaderAuthorization)
			if authHeader == "" {
				if allowPublic {
					return next(c)
				}
				return echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed authorization header")
			}

			tokenString, err := getTokenFromHeader(authHeader)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err)
			}

			claims, agent, key, err := verifyAgentRequest(db, tokenString, publicKey, c)
			if err != nil {
				return err
			}

			c.Set("agent", claims)
			c.Set("agent_auth", &AgentAuthContext{
				Claims: claims,
				Agent:  agent,
				Key:    key,
			})
			return next(c)
		}
	}
}

func verifyAgentRequest(db *gorm.DB, tokenString string, publicKey *rsa.PublicKey, c echo.Context) (*authn.AgentClaims, *relational.Agent, *relational.AgentServiceAccountKey, error) {
	claims, err := authn.VerifyAgentJWTToken(tokenString, publicKey)
	if err != nil {
		return nil, nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
	}

	var agent relational.Agent
	if err := db.Where("id = ?", claims.AgentID).First(&agent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
		}
		c.Logger().Errorf("failed to load agent for authenticated agent request: %v (agent_id=%v)", err, claims.AgentID)
		return nil, nil, nil, echo.NewHTTPError(http.StatusInternalServerError, "failed to load agent")
	}
	if !agent.IsActive {
		return nil, nil, nil, echo.NewHTTPError(http.StatusForbidden, "agent is inactive")
	}

	var key relational.AgentServiceAccountKey
	if err := db.Where("agent_id = ? AND id = ?", *agent.ID, claims.CredentialID).First(&key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
		}
		c.Logger().Errorf("failed to load agent key for authenticated agent request: %v (agent_id=%v credential_id=%v)", err, agent.ID, claims.CredentialID)
		return nil, nil, nil, echo.NewHTTPError(http.StatusInternalServerError, "failed to load agent key")
	}
	now := time.Now().UTC()
	if key.IsRevoked(now) {
		return nil, nil, nil, echo.NewHTTPError(http.StatusForbidden, "agent key is revoked")
	}
	if key.IsExpired(now) {
		return nil, nil, nil, echo.NewHTTPError(http.StatusForbidden, "agent key is expired")
	}

	return claims, &agent, &key, nil
}
