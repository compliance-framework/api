package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// DashboardHandler handles CRUD operations for dashboards.
type CatalogControlHandler struct {
	service *service.CatalogControlService
	sugar   *zap.SugaredLogger
}

// NewDashboardHandler creates a new DashboardHandler.
func NewCatalogControlHandler(l *zap.SugaredLogger, s *service.CatalogControlService) *CatalogControlHandler {
	return &CatalogControlHandler{
		sugar:   l,
		service: s,
	}
}

// Register registers the dashboard endpoints.
func (h *CatalogControlHandler) Register(api *echo.Group) {
	api.GET("/group/:class/:id", h.GetForGroup)
	api.GET("/children/:class/:id", h.GetForControl)
}

// GetForGroup godoc
//
//	@Summary		Get catalog controls for a group parent
//	@Description	Retrieves catalog controls associated with a group parent based on the parent's class and id.
//	@Tags			CatalogControls
//	@Produce		json
//	@Param			class	path		string	true	"Parent group class"
//	@Param			id		path		string	true	"Parent group id"
//	@Success		200		{object}	GenericDataListResponse[service.CatalogControl]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/controls/group/{class}/{id} [get]
func (h *CatalogControlHandler) GetForGroup(c echo.Context) error {
	results, err := h.service.FindFor(c.Request().Context(), service.CatalogItemParentIdentifier{
		ID:    c.Param("id"),
		Class: c.Param("class"),
		Type:  service.CatalogItemParentTypeGroup,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[service.CatalogControl]{
		Data: results,
	})
}

// GetForControl godoc
//
//	@Summary		Get catalog controls for a control parent
//	@Description	Retrieves catalog controls associated with a control parent based on the parent's class and id.
//	@Tags			CatalogControls
//	@Produce		json
//	@Param			class	path		string	true	"Parent control class"
//	@Param			id		path		string	true	"Parent control id"
//	@Success		200		{object}	GenericDataListResponse[service.CatalogControl]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/controls/children/{class}/{id} [get]
func (h *CatalogControlHandler) GetForControl(c echo.Context) error {
	results, err := h.service.FindFor(c.Request().Context(), service.CatalogItemParentIdentifier{
		ID:    c.Param("id"),
		Class: c.Param("class"),
		Type:  service.CatalogItemParentTypeControl,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[service.CatalogControl]{
		Data: results,
	})
}

// List godoc
//
//	@Summary		List catalog controls by parent
//	@Description	Retrieves catalog controls for a given parent identifier specified via query parameters (id, class, type).
//	@Tags			CatalogControls
//	@Produce		json
//	@Param			id		query		string	true	"Parent identifier id"
//	@Param			class	query		string	true	"Parent identifier class"
//	@Param			type	query		string	true	"Parent identifier type (catalog, group, or control)"
//	@Success		200		{object}	GenericDataListResponse[service.CatalogControl]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/controls [get]
func (h *CatalogControlHandler) List(c echo.Context) error {
	results, err := h.service.FindFor(c.Request().Context(), service.CatalogItemParentIdentifier{
		ID:    c.Param("id"),
		Class: c.Param("class"),
		Type:  service.CatalogItemParentType(c.Param("type")),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[service.CatalogControl]{
		Data: results,
	})
}
