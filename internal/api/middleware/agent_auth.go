package middleware

import (
	"crypto/rsa"

	"github.com/labstack/echo/v4"
)

// AgentJWTMiddleware returns an Echo middleware function that verifies JWT tokens using the provided RSA public key.
// TODO[gusfcarvalho]: this method is a simple noop for now
func AgentJWTMiddleware(publicKey *rsa.PublicKey) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			return next(c)
		}
	}
}
