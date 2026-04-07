package middleware

import (
	"crypto/rsa"
	"net/http"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// OptionalUserOrAgentJWTMiddleware accepts authenticated user JWTs, authenticated agent JWTs,
// or unauthenticated public requests when allowPublic is true.
func OptionalUserOrAgentJWTMiddleware(db *gorm.DB, publicKey *rsa.PublicKey, allowPublic bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == http.MethodOptions {
				return next(c)
			}

			if authHeader := c.Request().Header.Get(echo.HeaderAuthorization); authHeader != "" {
				tokenString, err := getTokenFromHeader(authHeader)
				if err != nil {
					return echo.NewHTTPError(http.StatusUnauthorized, err)
				}

				if claims, err := authn.VerifyJWTToken(tokenString, publicKey); err == nil {
					c.Set("user", claims)
					return next(c)
				}

				claims, agent, key, err := verifyAgentRequest(db, tokenString, publicKey, c)
				if err != nil {
					return err
				}
				c.Set("agent_claims", claims)
				c.Set("agent_auth", &AgentAuthContext{
					Claims: claims,
					Agent:  agent,
					Key:    key,
				})
				return next(c)
			}

			if authTokenCookie, err := c.Cookie("ccf_auth_token"); err == nil {
				claims, verifyErr := authn.VerifyJWTToken(authTokenCookie.Value, publicKey)
				if verifyErr != nil {
					return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
				}
				c.Set("user", claims)
				return next(c)
			}

			if allowPublic {
				return next(c)
			}
			return echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed authorization header")
		}
	}
}
