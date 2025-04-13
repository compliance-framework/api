package handler

import (
	"github.com/compliance-framework/configuration-service/internal"
	"github.com/google/uuid"
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// DashboardHandler handles CRUD operations for dashboards.
type CatalogGroupHandler struct {
	service *service.CatalogGroupService
	sugar   *zap.SugaredLogger
}

// NewDashboardHandler creates a new DashboardHandler.
func NewCatalogGroupHandler(l *zap.SugaredLogger, s *service.CatalogGroupService) *CatalogGroupHandler {
	return &CatalogGroupHandler{
		sugar:   l,
		service: s,
	}
}

// Register registers the dashboard endpoints.
func (h *CatalogGroupHandler) Register(api *echo.Group) {
	api.GET("/catalog/:catalog", h.Get)
	api.GET("/catalog/:catalog/:class/:id", h.GetForGroup)
	//api.GET("/:type/:class/:id", h.List)
}

// Get godoc
//
//	@Summary		Get catalog groups for a catalog parent
//	@Description	Retrieves catalog groups that belong to a catalog, identified by its unique catalog ID.
//	@Tags			CatalogGroups
//	@Produce		json
//	@Param			catalog	path		string	true	"Catalog ID"
//	@Success		200		{object}	GenericDataListResponse[service.CatalogGroup]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/groups/catalog/{catalog} [get]
func (h *CatalogGroupHandler) Get(ctx echo.Context) error {
	groups, err := h.service.FindFor(ctx.Request().Context(), service.CatalogItemParentIdentifier{
		CatalogId: uuid.MustParse(ctx.Param("catalog")),
		Type:      service.CatalogItemParentTypeCatalog,
	})
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[*service.CatalogGroup]{
		Data: groups,
	})
}

// GetForGroup godoc
//
//	@Summary		Get catalog groups for a group parent
//	@Description	Retrieves catalog groups that belong to a parent group, identified by its class and ID.
//	@Tags			CatalogGroups
//	@Produce		json
//	@Param			catalog	path		string	true	"Catalog ID"
//	@Param			class	path		string	true	"Parent group class"
//	@Param			id		path		string	true	"Parent group ID"
//	@Success		200		{object}	GenericDataListResponse[service.CatalogGroup]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/groups/children/{class}/{id} [get]
func (h *CatalogGroupHandler) GetForGroup(ctx echo.Context) error {
	groups, err := h.service.FindFor(ctx.Request().Context(), service.CatalogItemParentIdentifier{
		ID:        internal.Pointer(ctx.Param("id")),
		Class:     internal.Pointer(ctx.Param("class")),
		CatalogId: uuid.MustParse(ctx.Param("catalog")),
		Type:      service.CatalogItemParentTypeGroup,
	})
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[*service.CatalogGroup]{
		Data: groups,
	})
}
