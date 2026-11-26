package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
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
	// FollowSSPScope makes the filter follow its SSP's scope: filter becomes the base
	// expression and the stored filter is filter AND the scope, rewritten whenever the
	// scope changes. Requires sspId and a non-empty scope. On PUT, false stops following
	// and keeps the current effective filter; omitted keeps the current state.
	FollowSSPScope *bool `json:"followSspScope,omitempty" yaml:"-"`
	// Badge changes the filter's public badge (docs/filter-badges.md) and needs the
	// filter:publish permission unless it leaves the settings unchanged. Omitted keeps the
	// current settings (POST: unpublished defaults); null resets them to the defaults.
	Badge *filterBadgeRequest `json:"badge,omitempty" yaml:"-" extensions:"x-nullable"`

	// badgeSet records that the body had a badge key, so a null badge can be told apart
	// from an omitted one.
	badgeSet bool
}

// filterBadgeRequest is the badge object of a filter create or update. Omitted fields
// keep their current values on update and take the defaults on create.
type filterBadgeRequest struct {
	// Enabled publishes the badge at /api/public/badges/{slug}.svg; it requires a slug.
	Enabled *bool `json:"enabled,omitempty"`
	// Label is the badge's left-hand text: 1-64 characters after trimming, no control
	// characters.
	Label *string `json:"label,omitempty" example:"compliance"`
	// Slug is the public identifier: lowercase letters, digits and single hyphens, at
	// most 63 characters, unique across filters. null clears it and unpublishes.
	Slug *string `json:"slug,omitempty" extensions:"x-nullable" example:"payments-production"`

	// slugSet records that the body had a slug key, so a null slug can be told apart from
	// an omitted one.
	slugSet bool
}

func (r *filterBadgeRequest) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("badge must be an object")
	}
	*r = filterBadgeRequest{}
	if raw, ok := fields["enabled"]; ok {
		if err := json.Unmarshal(raw, &r.Enabled); err != nil {
			return fmt.Errorf("badge.enabled: %w", err)
		}
		if r.Enabled == nil {
			return errors.New("badge.enabled must be true or false")
		}
	}
	if raw, ok := fields["label"]; ok {
		if err := json.Unmarshal(raw, &r.Label); err != nil {
			return fmt.Errorf("badge.label: %w", err)
		}
		if r.Label == nil {
			return errors.New("badge.label must be a string")
		}
	}
	if raw, ok := fields["slug"]; ok {
		r.slugSet = true
		if err := json.Unmarshal(raw, &r.Slug); err != nil {
			return fmt.Errorf("badge.slug: %w", err)
		}
	}
	return nil
}

// UnmarshalJSON accepts sspId in either camelCase or kebab-case ("ssp-id"). The
// filters API convention is camelCase (see the SSPID doc comment above), but a client
// that kebab-cases this field hits Echo's default binder leaving it nil rather than
// erroring, so a PUT that means to move a filter's scope silently no-ops instead.
func (r *createFilterRequest) UnmarshalJSON(data []byte) error {
	type requestAlias struct {
		Name       string             `json:"name"`
		SSPIDCamel *uuid.UUID         `json:"sspId"`
		SSPIDKebab *uuid.UUID         `json:"ssp-id"`
		Filter     labelfilter.Filter `json:"filter"`
		Controls   *[]string          `json:"controls"`
		Components *[]string          `json:"components"`
		Follow     *bool              `json:"followSspScope"`
		Badge      json.RawMessage    `json:"badge"`
	}

	var decoded requestAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	r.Name = decoded.Name
	r.SSPID = decoded.SSPIDCamel
	if r.SSPID == nil {
		r.SSPID = decoded.SSPIDKebab
	}
	r.Filter = decoded.Filter
	r.Controls = decoded.Controls
	r.Components = decoded.Components
	r.FollowSSPScope = decoded.Follow
	r.Badge = nil
	r.badgeSet = decoded.Badge != nil
	if r.badgeSet && string(decoded.Badge) != "null" {
		r.Badge = &filterBadgeRequest{}
		if err := json.Unmarshal(decoded.Badge, r.Badge); err != nil {
			return err
		}
	}
	return nil
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

func (r *filteredSearchRequest) bind(ctx *echo.Context, p *labelfilter.Filter) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	p.Scope = r.Filter.Scope
	return nil
}
