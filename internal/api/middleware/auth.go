package middleware

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/compliance-framework/configuration-service/internal/authn"
	"github.com/labstack/echo/v4"
)

// JWTMiddleware returns an Echo middleware function that verifies JWT tokens using the provided RSA public key.
func JWTMiddleware(publicKey *rsa.PublicKey) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == http.MethodOptions {
				// Allow preflight requests without authentication
				return next(c)
			}

			authHeader := c.Request().Header.Get("Authorization")
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed authorization header")
			}

			tokenString := parts[1]
			claims, err := authn.VerifyJWTToken(tokenString, publicKey)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
			}

			// Store claims in context for downstream handlers
			c.Set("user", claims)
			return next(c)
		}
	}
}
