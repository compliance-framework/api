package oscal

import (
	"errors"
	"github.com/compliance-framework/configuration-service/internal/api"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
)

type CatalogHandler struct {
	sugar   *zap.SugaredLogger
	service *relational.CatalogService
}

func NewCatalogHandler(l *zap.SugaredLogger, service *relational.CatalogService) *CatalogHandler {
	return &CatalogHandler{
		sugar:   l,
		service: service,
	}
}

func (h *CatalogHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.POST("", h.Create)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
}

func (h *CatalogHandler) List(ctx echo.Context) error {
	catalogs, err := h.service.ListCatalogs()
	if err != nil {
		h.sugar.Errorw("Failed to list catalogs", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[relational.Catalog]{Data: catalogs})
}

func (h *CatalogHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	catalog, err := h.service.GetCatalog(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get catalog", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.Catalog]{Data: *catalog})
}

func (h *CatalogHandler) Create(ctx echo.Context) error {
	var catalog relational.Catalog
	if err := ctx.Bind(&catalog); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.service.CreateCatalog(&catalog); err != nil {
		h.sugar.Errorw("Failed to create catalog", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[relational.Catalog]{Data: catalog})
}

func (h *CatalogHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var catalog relational.Catalog
	if err := ctx.Bind(&catalog); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	// Enforce the URL ID
	catalog.ID = &id
	if err := h.service.UpdateCatalog(&catalog); err != nil {
		h.sugar.Errorw("Failed to update catalog", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.Catalog]{Data: catalog})
}

func (h *CatalogHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.service.DeleteCatalog(id); err != nil {
		h.sugar.Errorw("Failed to delete catalog", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.NoContent(http.StatusNoContent)
}
