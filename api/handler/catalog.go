package handler

import (
	"github.com/compliance-framework/configuration-service/domain/service"
	"github.com/labstack/echo/v4"
	"net/http"
)

type CatalogHandler struct {
	service *service.Catalog
}

func NewCatalogHandler(s *service.Catalog) *CatalogHandler {
	return &CatalogHandler{service: s}
}

func (h *CatalogHandler) Register(api *echo.Group) {
	api.GET("/catalog/controls/:id", h.GetControl)
}

func (h *CatalogHandler) GetControl(c echo.Context) error {
	id := c.Param("id")
	obj, err := h.service.GetControl(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, obj)
}
