package handler

import (
	"github.com/compliance-framework/configuration-service/store"
	"github.com/labstack/echo/v4"
)

type CatalogHandler struct {
	store store.CatalogStore
}

func NewCatalogHandler(s store.CatalogStore) *CatalogHandler {
	return &CatalogHandler{store: s}
}

func (h *CatalogHandler) Register(api *echo.Group) {
	api.POST("/catalog", h.CreateCatalog)
}

func (h *CatalogHandler) CreateCatalog(c echo.Context) error {
	catalog, err := h.store.CreateCatalog(nil)
	if err != nil {
		return err
	}
	return c.JSON(200, catalog)
}
