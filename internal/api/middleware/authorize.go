package middleware

import (
	"net/http"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Authorizer is CCF's Policy Enforcement Point (PEP). It builds an authz.Subject
// from the request's authenticated claims, asks the configured PDP for a
// decision, and enforces it. It supplies facts only and holds no policy logic.
//
// Enforcement outcomes:
//   - allow                       -> the request proceeds;
//   - explicit deny               -> 403 (the PDP reason is logged, never echoed);
//   - evaluator error, fail open  -> the request proceeds;
//   - evaluator error, fail closed-> 500 (an evaluator error is an internal
//     failure; 403 is reserved for an explicit policy deny).
type Authorizer struct {
	pdp      authz.PDP
	logger   *zap.SugaredLogger
	failMode authz.FailMode
}

// NewAuthorizer builds an Authorizer around an already-constructed PDP.
func NewAuthorizer(pdp authz.PDP, logger *zap.SugaredLogger, failMode authz.FailMode) *Authorizer {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Authorizer{pdp: pdp, logger: logger, failMode: failMode}
}

// NewAuthorizerFromConfig constructs an Authorizer for the driver named in
// cfg.AuthZ (defaulting to the builtin engine, failing closed) using the
// embedded authorization manifest. A misconfigured driver or an unloadable
// manifest is fatal: the server must not start enforcing with the wrong engine.
func NewAuthorizerFromConfig(db *gorm.DB, cfg *config.Config, logger *zap.SugaredLogger) *Authorizer {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	driver := config.AuthZDriverBuiltin
	failMode := authz.FailClosed
	if cfg != nil && cfg.AuthZ != nil {
		if cfg.AuthZ.Driver != "" {
			driver = cfg.AuthZ.Driver
		}
		failMode = authz.ParseFailMode(cfg.AuthZ.FailMode)
	}

	manifest, err := authz.DefaultManifest()
	if err != nil {
		logger.Fatalw("authz: failed to load authorization manifest", "error", err)
	}

	pdp, err := authz.Open(driver, authz.Options{
		DB:       db,
		Config:   cfg,
		Logger:   logger,
		Manifest: manifest,
	})
	if err != nil {
		logger.Fatalw("authz: failed to initialize authorization driver", "driver", driver, "error", err)
	}

	logger.Debugw("authz: enforcement initialized", "driver", driver, "failMode", string(failMode))
	return NewAuthorizer(pdp, logger, failMode)
}

type authorizeOptions struct {
	allowPublic     bool
	resourceIDParam string
}

// AuthorizeOption customizes a single Authorize middleware.
type AuthorizeOption func(*authorizeOptions)

// WithPublicAccess lets anonymous requests reach the PDP with the allow_public
// fact set, for routes that opt into public access (e.g. public agent ingest).
func WithPublicAccess(allow bool) AuthorizeOption {
	return func(o *authorizeOptions) { o.allowPublic = allow }
}

// WithResourceIDParam names the route param holding the resource instance id
// (e.g. "id"); its value is passed to the PDP as Resource.ID.
func WithResourceIDParam(name string) AuthorizeOption {
	return func(o *authorizeOptions) { o.resourceIDParam = name }
}

// Authorize returns middleware that enforces (resource, action) for the request
// through the configured PDP. It must run after an authentication middleware has
// populated the request context with user or agent claims.
func (a *Authorizer) Authorize(resource, action string, opts ...AuthorizeOption) echo.MiddlewareFunc {
	var o authorizeOptions
	for _, opt := range opts {
		opt(&o)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == http.MethodOptions {
				// CORS preflight is handled by the global CORS middleware; never
				// gate it here.
				return next(c)
			}

			subject := subjectFromContext(c)

			res := authz.Resource{Type: resource}
			if o.resourceIDParam != "" {
				res.ID = c.Param(o.resourceIDParam)
			}

			reqCtx := map[string]any{
				"allow_public": o.allowPublic,
				"method":       c.Request().Method,
			}

			if a.pdp == nil {
				a.logger.Errorw("authz: no PDP configured; denying", "resource", resource, "action", action)
				return echo.NewHTTPError(http.StatusForbidden, "forbidden")
			}

			decision, err := a.pdp.Evaluate(c.Request().Context(), subject, action, res, reqCtx)
			if err != nil {
				a.logger.Errorw("authz: evaluation error",
					"resource", resource, "action", action, "subjectType", subject.Type, "error", err)
				if a.failMode == authz.FailOpen {
					return next(c)
				}
				return echo.NewHTTPError(http.StatusInternalServerError, "authorization check failed")
			}

			if !decision.Allow {
				a.logger.Warnw("authz: request denied",
					"resource", resource, "action", action,
					"subjectType", subject.Type, "subjectID", subject.ID,
					"reason", decision.Reason)
				return echo.NewHTTPError(http.StatusForbidden, "forbidden")
			}

			return next(c)
		}
	}
}

// subjectFromContext builds an authz.Subject from the authenticated claims an
// upstream authn middleware stored in the request context, or an anonymous
// subject when none are present.
func subjectFromContext(c echo.Context) authz.Subject {
	if claims, ok := c.Get("user").(*authn.UserClaims); ok && claims != nil {
		return authz.Subject{
			Type: authz.SubjectUser,
			ID:   claims.Subject,
			Props: map[string]any{
				"email": claims.Subject,
			},
		}
	}
	if claims, ok := c.Get("agent_claims").(*authn.AgentClaims); ok && claims != nil {
		return authz.Subject{
			Type: authz.SubjectAgent,
			ID:   claims.Subject,
			Props: map[string]any{
				"service_account": claims.Subject,
				"agent_id":        claims.AgentID,
				"auth_method":     claims.AuthMethod,
			},
		}
	}
	return authz.Subject{Type: authz.SubjectAnonymous}
}
