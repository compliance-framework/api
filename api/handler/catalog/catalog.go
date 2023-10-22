package catalog

import (
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
	"github.com/compliance-framework/configuration-service/store"
	"github.com/labstack/echo/v4"
	"net/http"
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

// CreateCatalog godoc
// @Summary Create a catalog
// @Description Create a catalog with the given title
// @Accept  json
// @Produce  json
// @Param   catalog body createCatalogRequest true "Catalog to add"
// @Success 201 {object} catalogIdResponse
// @Failure 401 {object} api.Error
// @Failure 422 {object} api.Error
// @Failure 500 {object} api.Error
// @Router /api/catalog [post]
func (h *CatalogHandler) CreateCatalog(ctx echo.Context) error {
	var c catalog.Catalog
	req := newCreateCatalogRequest()
	if err := req.bind(ctx, &c); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	id, err := h.store.CreateCatalog(&c)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, catalogIdResponse{
		Id: id.(string),
	})
}
