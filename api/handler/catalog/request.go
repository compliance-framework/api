package catalog

import (
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/labstack/echo/v4"
)

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
