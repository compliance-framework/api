package handler

import (
	"errors"
	"net/http"
	"sort"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// PermissionsHandler serves GET /me/permissions: the set of (resource, action) pairs the
// authenticated subject may perform, computed in a single batch PDP call over the manifest
// vocabulary. The UI uses it to hide actions the user can't take (BCH-1318). It holds
// facts only — no policy logic — and reuses the PEP's subject derivation.
type PermissionsHandler struct {
	pdp      authz.PDP
	manifest *authz.Manifest
	failMode authz.FailMode
	logger   *zap.SugaredLogger
}

// NewPermissionsHandler constructs the handler. A nil logger becomes a no-op; an empty
// fail mode defaults to fail-closed.
func NewPermissionsHandler(pdp authz.PDP, manifest *authz.Manifest, failMode authz.FailMode, logger *zap.SugaredLogger) *PermissionsHandler {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	if failMode == "" {
		failMode = authz.FailClosed
	}
	return &PermissionsHandler{pdp: pdp, manifest: manifest, failMode: failMode, logger: logger}
}

// Register mounts the route on a group that already enforces authentication.
func (h *PermissionsHandler) Register(g *echo.Group) {
	g.GET("/permissions", h.GetPermissions)
}

type permissionsSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type permissionsResponse struct {
	Subject     permissionsSubject  `json:"subject"`
	Permissions map[string][]string `json:"permissions"`
}

// GetPermissions enumerates every manifest resource × action for the current subject,
// asks the PDP for all decisions in one batch, and returns the allowed map. Resources are
// always present (so the UI knows the full vocabulary) with their allowed actions; ordering
// is deterministic (resources sorted, actions in manifest order).
func (h *PermissionsHandler) GetPermissions(c echo.Context) error {
	subject := middleware.SubjectFromContext(c)
	subjectView := permissionsSubject{Type: subject.Type, ID: subject.ID}

	resources := make([]string, 0, len(h.manifest.Resources))
	for name := range h.manifest.Resources {
		resources = append(resources, name)
	}
	sort.Strings(resources)

	// Pre-seed every resource with an empty allow-list so the response shape is stable
	// regardless of decisions or fail mode.
	perms := make(map[string][]string, len(resources))
	for _, r := range resources {
		perms[r] = []string{}
	}

	type pair struct{ resource, action string }
	reqs := make([]authz.EvalRequest, 0)
	index := make([]pair, 0)
	for _, resource := range resources {
		for _, action := range h.manifest.Resources[resource].Actions {
			// Type-level capability check (no resource instance / request context), which
			// is exactly what UI hints need; instance-level checks stay on the PEP.
			reqs = append(reqs, authz.EvalRequest{
				Subject:  subject,
				Action:   action,
				Resource: authz.Resource{Type: resource},
			})
			index = append(index, pair{resource, action})
		}
	}

	decisions, err := h.pdp.Evaluations(c.Request().Context(), reqs)
	if err != nil {
		if errors.Is(err, authz.ErrUnavailable) {
			h.logger.Warnw("authz PDP unavailable for /me/permissions", "failMode", h.failMode, "error", err)
			if h.failMode == authz.FailOpen {
				for _, r := range resources {
					perms[r] = append([]string{}, h.manifest.Resources[r].Actions...)
				}
			}
			// Fail closed leaves the pre-seeded empty lists (UI hides everything).
			return c.JSON(http.StatusOK, permissionsResponse{Subject: subjectView, Permissions: perms})
		}
		h.logger.Errorw("authz evaluation failed for /me/permissions", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "authorization error")
	}
	if len(decisions) != len(index) {
		h.logger.Errorw("authz returned wrong decision count for /me/permissions",
			"want", len(index), "got", len(decisions))
		return echo.NewHTTPError(http.StatusInternalServerError, "authorization error")
	}

	for i, d := range decisions {
		if d.Allow {
			perms[index[i].resource] = append(perms[index[i].resource], index[i].action)
		}
	}
	return c.JSON(http.StatusOK, permissionsResponse{Subject: subjectView, Permissions: perms})
}
