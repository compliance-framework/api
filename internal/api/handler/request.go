package handler

import (
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/labstack/echo/v4"
	"gorm.io/datatypes"
)

// createPlanRequest defines the request payload for method Create
type createFilterRequest struct {
	Name     string             `json:"name" yaml:"name" validate:"required"`
	Filter   labelfilter.Filter `json:"filter" yaml:"filter" validate:"required"`
	Controls *[]string          `json:"controls" yaml:"controls"`
}

func (r *createFilterRequest) bind(ctx echo.Context, p *relational.Filter) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	p.Name = r.Name
	p.Filter = datatypes.NewJSONType(r.Filter)
	return nil
}

// createPlanRequest defines the request payload for method Create
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
