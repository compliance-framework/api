package middleware

import (
	"errors"
	"net/http"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// PEP is the single Policy Enforcement Point. It builds an authz Subject from the
// authenticated principal in the request context and a Resource from the route, asks the
// configured PDP for a decision, and enforces the result: allow → next; deny → 403 (the
// reason is logged, never echoed to the client); PDP unavailable → the configured fail
// mode; any other error → 500. The PEP supplies facts only and holds no policy logic.
type PEP struct {
	pdp      authz.PDP
	failMode authz.FailMode
	logger   *zap.SugaredLogger
}

// NewPEP constructs a PEP. A nil logger is replaced with a no-op logger and an empty fail
// mode defaults to fail-closed.
func NewPEP(pdp authz.PDP, failMode authz.FailMode, logger *zap.SugaredLogger) *PEP {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	if failMode == "" {
		failMode = authz.FailClosed
	}
	return &PEP{pdp: pdp, failMode: failMode, logger: logger}
}

// Authorize returns middleware that enforces (resource, action) for the matched route.
func (p *PEP) Authorize(resource, action string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			subject := subjectFromContext(c)
			res := authz.Resource{Type: resource, ID: c.Param("id")}
			reqCtx := map[string]any{
				"method": c.Request().Method,
				"path":   c.Path(),
			}

			decision, err := p.pdp.Evaluate(c.Request().Context(), subject, action, res, reqCtx)
			if err != nil {
				if errors.Is(err, authz.ErrUnavailable) {
					p.logger.Warnw("authz PDP unavailable",
						"resource", resource, "action", action, "failMode", p.failMode, "error", err)
					if p.failMode == authz.FailOpen {
						return next(c)
					}
					return echo.NewHTTPError(http.StatusForbidden, "forbidden")
				}
				p.logger.Errorw("authz evaluation failed",
					"resource", resource, "action", action, "error", err)
				return echo.NewHTTPError(http.StatusInternalServerError, "authorization error")
			}

			if !decision.Allow {
				p.logger.Infow("authz denied",
					"resource", resource, "action", action,
					"subjectType", subject.Type, "subjectID", subject.ID,
					"reason", decision.Reason)
				return echo.NewHTTPError(http.StatusForbidden, "forbidden")
			}
			return next(c)
		}
	}
}

// subjectFromContext derives the authz Subject from the principal the authn middleware
// placed in the context: an authenticated user, an authenticated agent, or an anonymous
// subject on public-allowed routes. Attributes are intentionally minimal in Phase 1; the
// authoritative attribute surface is designed in BCH-1319.
func subjectFromContext(c echo.Context) authz.Subject {
	if claims, ok := c.Get("user").(*authn.UserClaims); ok && claims != nil {
		return authz.Subject{
			Type: "user",
			ID:   claims.Subject,
			Props: map[string]any{
				"given_name":  claims.GivenName,
				"family_name": claims.FamilyName,
			},
		}
	}
	if claims, ok := c.Get("agent_claims").(*authn.AgentClaims); ok && claims != nil {
		return authz.Subject{
			Type: "agent",
			ID:   claims.Subject,
			Props: map[string]any{
				"agent_id":    claims.AgentID,
				"auth_method": claims.AuthMethod,
			},
		}
	}
	return authz.Subject{Type: "anonymous"}
}
