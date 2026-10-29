package handler

import (
	"errors"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational/sspscope"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

// RegisterSSPScopedRoutes mounts the SSP-scoped evidence reads, which read scopes through
// scope, on the SSP group (/oscal/system-security-plans). The caller passes user auth and
// the SSP read guard: unlike the public evidence reads, these routes reveal which evidence
// an SSP claims.
func (h *EvidenceHandler) RegisterSSPScopedRoutes(api *echo.Group, scope *sspscope.Service, middlewares ...echo.MiddlewareFunc) {
	h.sspScope = scope
	api.POST("/:id/evidence/search", h.SSPScopedSearch, middlewares...)
	api.POST("/:id/evidence/status-over-time", h.SSPScopedStatusOverTime, middlewares...)
}

// sspScopeRestriction loads the scope of the SSP named by the id path parameter. On
// failure it has already written the response and returns ok=false.
func (h *EvidenceHandler) sspScopeRestriction(ctx *echo.Context) (scopeRestriction, bool) {
	sspID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}
	scope, hasEntries, err := h.sspScope.Filter(sspID)
	if errors.Is(err, sspscope.ErrSSPNotFound) {
		_ = ctx.JSON(http.StatusNotFound, api.NewError(err))
		return nil, false
	}
	if err != nil {
		h.sugar.Errorw("Failed to load SSP scope", "ssp", sspID, "error", err)
		_ = ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		return nil, false
	}
	return func(filter labelfilter.Filter) (labelfilter.Filter, bool) {
		if !hasEntries {
			return labelfilter.Filter{}, false
		}
		return sspscope.And(filter, scope), true
	}, true
}
