package handler

import (
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/labstack/echo/v4"
)

// createCatalogRequest defines the request payload for method CreateCatalog
type createCatalogRequest struct {
	Catalog struct {
		Title string `json:"title" validate:"required"`
	}
}

func newCreateCatalogRequest() *createCatalogRequest {
	return &createCatalogRequest{}
}

func (r *createCatalogRequest) bind(ctx echo.Context, c *domain.Catalog) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	c.Title = r.Catalog.Title
	return nil
}

// createPlanRequest defines the request payload for method Create
// TODO: Using minimal data for now, we might need to expand it later
type createPlanRequest struct {
	Title string `json:"title" validate:"required"`
}

func (r *createPlanRequest) bind(ctx echo.Context, p *domain.Plan) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	p.Title = r.Title
	return nil
}

type addAssetRequest struct {
	AssetUuid string `json:"assetUuid" validate:"required"`
	Type      string `json:"type" validate:"required"`
}

func (r *addAssetRequest) bind(ctx echo.Context, p *domain.Plan) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	return nil
}
