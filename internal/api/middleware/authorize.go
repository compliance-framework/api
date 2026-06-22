package middleware

import (
	"errors"
	"net/http"
	"time"

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

// AuthorizeOption configures how a route binds request data into the resource the PEP
// hands the PDP.
type AuthorizeOption func(*authorizeConfig)

type authorizeConfig struct {
	idParam     string            // path param identifying the resource instance (Resource.ID)
	scopeParams map[string]string // resource-prop attribute name -> path param name
}

// ScopeParam binds a URL path parameter as a C0 scope attribute on the resource, so a scope
// key the URL already carries is supplied for free (no row load). The attribute name is the
// snake_case form of the param, e.g. ScopeParam("sspId") exports resource prop ssp_id from
// c.Param("sspId"), and ScopeParam("parentId") exports parent_id. Routes that don't carry
// the scope key in the URL fall back to a C1 row-load in a later phase (BCH-1319 §9).
func ScopeParam(param string) AuthorizeOption {
	return func(cfg *authorizeConfig) {
		if cfg.scopeParams == nil {
			cfg.scopeParams = map[string]string{}
		}
		cfg.scopeParams[camelToSnake(param)] = param
	}
}

// ResourceIDParam overrides which path parameter identifies the resource instance. The
// default is "id"; SSP-rooted routes whose primary key is ":sspId", for example, pass
// ResourceIDParam("sspId").
func ResourceIDParam(param string) AuthorizeOption {
	return func(cfg *authorizeConfig) { cfg.idParam = param }
}

// Authorize returns middleware that enforces (resource, action) for the matched route.
// Options bind route data (the id param, scope params) into the evaluation tuple.
func (p *PEP) Authorize(resource, action string, opts ...AuthorizeOption) echo.MiddlewareFunc {
	cfg := authorizeConfig{idParam: "id"}
	for _, o := range opts {
		o(&cfg)
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			subject := SubjectFromContext(c)
			res := authz.Resource{Type: resource, ID: c.Param(cfg.idParam)}
			for attr, param := range cfg.scopeParams {
				if v := c.Param(param); v != "" {
					if res.Props == nil {
						res.Props = map[string]any{}
					}
					res.Props[attr] = v
				}
			}
			reqCtx := map[string]any{
				"method": c.Request().Method,
				"path":   c.Path(),
			}

			start := time.Now()
			decision, err := p.pdp.Evaluate(c.Request().Context(), subject, action, res, reqCtx)
			latency := time.Since(start)

			if err != nil {
				if errors.Is(err, authz.ErrUnavailable) {
					allow := p.failMode == authz.FailOpen
					p.audit(subject, action, res, authz.Decision{Allow: allow, Reason: "pdp unavailable: fail-" + string(p.failMode)}, latency)
					p.logger.Warnw("authz PDP unavailable",
						"resource", resource, "action", action, "failMode", p.failMode, "error", err)
					if allow {
						return next(c)
					}
					return echo.NewHTTPError(http.StatusForbidden, "forbidden")
				}
				p.audit(subject, action, res, authz.Decision{Allow: false, Reason: "evaluation error"}, latency)
				p.logger.Errorw("authz evaluation failed",
					"resource", resource, "action", action, "error", err)
				return echo.NewHTTPError(http.StatusInternalServerError, "authorization error")
			}

			p.audit(subject, action, res, decision, latency)
			if !decision.Allow {
				return echo.NewHTTPError(http.StatusForbidden, "forbidden")
			}
			return next(c)
		}
	}
}

// audit emits the decision audit record for every PEP call (subject, action, resource,
// decision, latency), the immutable trail of who was allowed/denied what (parent design §5,
// Phase 2). The PDP reason is logged here but, as everywhere in the PEP, never echoed to
// the client. Emitted at info so it is always captured.
func (p *PEP) audit(s authz.Subject, action string, r authz.Resource, d authz.Decision, latency time.Duration) {
	outcome := "deny"
	if d.Allow {
		outcome = "allow"
	}
	p.logger.Infow("authz decision",
		"audit", true,
		"decision", outcome,
		"subjectType", s.Type,
		"subjectID", s.ID,
		"resource", r.Type,
		"resourceID", r.ID,
		"action", action,
		"reason", d.Reason,
		"latencyMs", float64(latency.Microseconds())/1000.0,
	)
}

// camelToSnake lowercases a camelCase path param into the snake_case attribute name the
// manifest uses (sspId -> ssp_id, parentId -> parent_id). A run of capitals is treated as a
// single token, so trailing acronyms map correctly (userID -> user_id, oscalID -> oscal_id,
// HTTPServer -> http_server) rather than being split letter-by-letter. Already-snake or
// all-lower names pass through unchanged.
func camelToSnake(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			var prev byte
			if i > 0 {
				prev = s[i-1]
			}
			prevLowerOrDigit := (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9')
			prevUpper := prev >= 'A' && prev <= 'Z'
			nextLower := i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z'
			// Boundary before an uppercase letter: after a lowercase/digit, or at the start
			// of a new word inside a run of capitals (e.g. the "S" in "HTTPServer"). A capital
			// that merely continues an acronym (the "TTP" in "HTTP") gets no underscore.
			if prev != '_' && (prevLowerOrDigit || (prevUpper && nextLower)) {
				b = append(b, '_')
			}
			ch += 'a' - 'A'
		}
		b = append(b, ch)
	}
	return string(b)
}

// SubjectFromContext derives the authz Subject from the principal the authn middleware
// placed in the context: an authenticated user, an authenticated agent, or an anonymous
// subject on public-allowed routes. It is the single source of subject derivation, shared
// by the PEP and the /me/permissions handler. Attributes are intentionally minimal in
// Phase 1; the authoritative attribute surface is designed in BCH-1319.
func SubjectFromContext(c echo.Context) authz.Subject {
	if claims, ok := c.Get("user").(*authn.UserClaims); ok && claims != nil {
		props := map[string]any{
			"given_name":  claims.GivenName,
			"family_name": claims.FamilyName,
		}
		// user_uuid is the C0 subject attribute owner policies match against the ownership
		// FKs (BCH-1319 §7). Older tokens issued before the claim landed omit it; only
		// surface it when present so the attribute is absent rather than empty.
		if claims.UserUUID != "" {
			props["user_uuid"] = claims.UserUUID
		}
		return authz.Subject{
			Type:  "user",
			ID:    claims.Subject,
			Props: props,
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
