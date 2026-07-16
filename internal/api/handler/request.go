package handler

import (
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func ParseIntervalListQueryParam(intervalQuery string, def []time.Duration) ([]time.Duration, error) {
	if intervalQuery == "" {
		return def, nil
	}

	var intervals []time.Duration
	userIntervals := strings.Split(intervalQuery, ",")
	for _, interval := range userIntervals {
		dur, err := time.ParseDuration(interval)
		if err != nil {
			return nil, err
		}
		intervals = append(intervals, dur)
	}
	return intervals, nil
}

// createFilterRequest defines the request payload for method Create
type createFilterRequest struct {
	Name string `json:"name" yaml:"name" validate:"required"`
	// System Security Plan ID. On PUT, omitted or null clears the binding to global.
	SSPID      *uuid.UUID         `json:"sspId" yaml:"ssp_id" extensions:"x-nullable" example:"00000000-0000-0000-0000-000000000000" swaggertype:"string" format:"uuid"`
	Filter     labelfilter.Filter `json:"filter" yaml:"filter" validate:"required"`
	Controls   *[]string          `json:"controls" yaml:"controls"`
	Components *[]string          `json:"components" yaml:"components"`
}

// attachFilterResponsibilityRequest is the body for POST /filters/:id/responsibilities.
// camelCase JSON, the filters-API convention — clients must NOT kebab-case this body.
type attachFilterResponsibilityRequest struct {
	// The upstream ControlImplementationResponsibility this filter should evidence.
	ResponsibilityUUID uuid.UUID `json:"responsibilityUuid" validate:"required" swaggertype:"string" format:"uuid"`
	// The DOWNSTREAM SSP that inherits the responsibility (matched against
	// ssp_leverage_links.downstream_ssp_id).
	SSPID uuid.UUID `json:"sspId" validate:"required" swaggertype:"string" format:"uuid"`
	// Optional control to also link the filter to (so control-level compliance
	// surfaces include it). The link's provenance is recorded: detaching the
	// responsibility removes the control link only if this attach created it.
	ControlID *string `json:"controlId"`
}

// SetCatalogActiveRequest is the body for toggling a catalog's active state.
// Active is a pointer so a missing field is rejected rather than defaulting to
// false and silently deactivating the catalog.
type SetCatalogActiveRequest struct {
	Active *bool `json:"active" validate:"required"`
}

// TODO: Using minimal data for now, we might need to expand it later
type filteredSearchRequest struct {
	Filter labelfilter.Filter `json:"filter" yaml:"filter" validate:"required"`
}

func (r *filteredSearchRequest) bind(ctx echo.Context, p *labelfilter.Filter) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	p.Scope = r.Filter.Scope
	return nil
}
