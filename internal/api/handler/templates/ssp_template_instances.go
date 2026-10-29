package templates

import (
	"fmt"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

type sspTemplateInstanceResponse struct {
	KeyValues      map[string]any                 `json:"key-values"`
	KeyHash        string                         `json:"key-hash"` // the id the forget route takes
	SSPID          *uuid.UUID                     `json:"ssp-id"`   // null once the SSP was deleted
	Title          *string                        `json:"title"`
	CreatedAt      time.Time                      `json:"created-at"`
	LastSeenAt     time.Time                      `json:"last-seen-at"`
	Stale          bool                           `json:"stale"`
	LastError      *string                        `json:"last-error"`
	SkippedEntries int                            `json:"skipped-entries"` // learned values rejected as invalid on the last run
	SkippedSample  []relational.SkippedScopeEntry `json:"skipped-sample"`
}

// Run godoc
//
//	@Summary		Run SSP template discovery
//	@Description	Queue a discovery run of the template now. A run already queued for it is not queued twice.
//	@Tags			SSP Templates
//	@Param			id	path	string	true	"SSP template ID"
//	@Success		202
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		409	{object}	api.Error	"the template is disabled"
//	@Failure		500	{object}	api.Error
//	@Failure		503	{object}	api.Error	"background jobs are not available"
//	@Security		OAuth2Password
//	@Router			/admin/ssp-templates/{id}/run [post]
func (h *SSPTemplateHandler) Run(ctx *echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.service.CheckRunnable(id); err != nil {
		return h.serviceError(ctx, "failed to load SSP template", err)
	}
	if h.enqueuer == nil {
		return ctx.JSON(http.StatusServiceUnavailable, api.NewError(fmt.Errorf("background jobs are not available")))
	}
	if err := h.enqueuer.EnqueueSSPTemplateDiscovery(ctx.Request().Context(), id); err != nil {
		return templateInternalServerError(ctx, h.sugar, "failed to enqueue SSP template discovery", err)
	}
	return ctx.NoContent(http.StatusAccepted)
}

// ListSSPs godoc
//
//	@Summary		List the SSPs an SSP template created
//	@Description	List the template's instances, newest first: the SSP (null once deleted), when it was last seen in evidence, whether it is stale, and the last run's error and skipped entries.
//	@Tags			SSP Templates
//	@Produce		json
//	@Param			id		path		string	true	"SSP template ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[sspTemplateInstanceResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/ssp-templates/{id}/ssps [get]
func (h *SSPTemplateHandler) ListSSPs(ctx *echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	instances, total, err := h.service.Instances(id, pagination.Limit, pagination.Offset)
	if err != nil {
		return h.serviceError(ctx, "failed to list SSP template instances", err)
	}
	staleBefore := time.Now().Add(-h.staleAfter)
	resp := make([]sspTemplateInstanceResponse, 0, len(instances))
	for _, instance := range instances {
		resp = append(resp, sspTemplateInstanceResponse{
			KeyValues:      instance.KeyValues,
			KeyHash:        instance.KeyHash,
			SSPID:          instance.SSPID,
			Title:          instance.Title,
			CreatedAt:      instance.CreatedAt,
			LastSeenAt:     instance.LastSeenAt,
			Stale:          instance.SSPID != nil && instance.LastSeenAt.Before(staleBefore),
			LastError:      instance.LastError,
			SkippedEntries: instance.SkippedEntries,
			SkippedSample:  append([]relational.SkippedScopeEntry{}, instance.SkippedSample...),
		})
	}
	return ctx.JSON(http.StatusOK, svc.NewListResponse(resp, total, pagination.Page, pagination.Limit))
}

// Forget godoc
//
//	@Summary		Forget a deleted SSP of an SSP template
//	@Description	Delete the record of an SSP the template created and a user then deleted, so the next discovery run creates it again. Only allowed once the SSP was deleted (409 otherwise).
//	@Tags			SSP Templates
//	@Param			id		path	string	true	"SSP template ID"
//	@Param			keyHash	path	string	true	"Instance key hash"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		409	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/ssp-templates/{id}/ssps/{keyHash} [delete]
func (h *SSPTemplateHandler) Forget(ctx *echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.service.Forget(id, ctx.Param("keyHash")); err != nil {
		return h.serviceError(ctx, "failed to forget SSP template instance", err)
	}
	return ctx.NoContent(http.StatusNoContent)
}
