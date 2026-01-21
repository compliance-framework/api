package handler

import (
	"errors"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
)

type FilterWithEvidenceStatusCount struct {
	Name   string                `json:"name"`
	Filter labelfilter.Filter    `json:"filter"`
	Counts []EvidenceStatusCount `json:"counts"`
}

// ComputeByImplementedRequirement godoc
//
//	@Summary		Computes filters for implemented requirements
//	@Description	Computes filters by composing control filters and component filters for
//					an implemented requirement, and retrieves their evidence counts and statuses.
//	@Tags			Evidence
//	@Produce		json
//	@Param			reqId	path		string	true	"Implemented Requirement ID"
//	@Success		200	{object}	GenericDataListResponse[handler.FilterWithEvidenceStatusCount]
//	@Failure		500	{object}	api.Error
//	@Router			/filters/computed/by-implemented-requirement/{reqId} [get]
func (h *FilterHandler) ComputeByImplementedRequirement(ctx echo.Context) error {
	idParam := ctx.Param("reqId")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var requirement relational.ImplementedRequirement
	if err := h.db.Preload("ByComponent").First(&requirement, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var control relational.Control
	if err := h.db.Preload("Filters").First(&control, "id = ?", requirement.ControlId).Error; err != nil {
		// Not checking for ErrRecordNotFound here because it shouldn't be possible, so the error is internal
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	controlScopes := make(map[string]labelfilter.Scope, len(control.Filters))
	for _, filter := range control.Filters {
		data := filter.Filter.Data()
		if data.Scope == nil {
			continue
		}
		controlScopes[filter.Name] = *data.Scope
	}

	computedFilters := make(map[string]labelfilter.Filter, len(control.Filters))
	if len(requirement.ByComponents) > 0 {
		componentScopes := []labelfilter.Scope{}
		for _, byComponent := range requirement.ByComponents {
			var component relational.SystemComponent
			if err := h.db.Preload("Filters").First(&component, "id = ?", byComponent.ComponentUUID).Error; err != nil {
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}

			for _, filter := range component.Filters {
				data := filter.Filter.Data()
				if data.Scope == nil {
					continue
				}
				componentScopes = append(componentScopes, *data.Scope)
			}
		}

		intersection := labelfilter.Scope{
			Query: &labelfilter.Query{
				Operator: "or",
				Scopes:   componentScopes,
			},
		}

		for name, controlScope := range controlScopes {
			computedFilters[name] = labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Query: &labelfilter.Query{
						Operator: "and",
						Scopes:   []labelfilter.Scope{controlScope, intersection},
					},
				},
			}
		}
	} else {
		for name, controlScope := range controlScopes {
			computedFilters[name] = labelfilter.Filter{Scope: &controlScope}
		}
	}

	eg := errgroup.Group{}
	ch := make(chan FilterWithEvidenceStatusCount, len(computedFilters))
	defer close(ch)
	for name, filter := range computedFilters {
		eg.Go(h.getFilteredEvidenceCounts(ch, name, filter))
	}

	if err := eg.Wait(); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	results := make([]FilterWithEvidenceStatusCount, 0, len(computedFilters))
	for res := range ch {
		results = append(results, res)
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[FilterWithEvidenceStatusCount]{Data: results})
}

func (h *FilterHandler) getFilteredEvidenceCounts(ch chan<- FilterWithEvidenceStatusCount, name string, filter labelfilter.Filter) func() error {
	return func() error {
		latestQuery := relational.GetLatestEvidenceStreamsQuery(h.db.Session(&gorm.Session{}))
		q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, h.db)
		if err != nil {
			return err
		}

		rows := []EvidenceStatusCount{}
		tx := q.Model(&relational.Evidence{}).
			Select("count(*) as count, status->>'state' as status").
			Group("status->>'state'").
			Scan(&rows)

		if err := tx.Error; err != nil {
			return err
		}

		ch <- FilterWithEvidenceStatusCount{
			Name:   name,
			Filter: filter,
			Counts: rows,
		}

		return nil
	}
}
