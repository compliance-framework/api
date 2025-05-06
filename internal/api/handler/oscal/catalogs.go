package oscal

import (
	"errors"
	"github.com/compliance-framework/configuration-service/internal/api"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
)

type CatalogHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewCatalogHandler(l *zap.SugaredLogger, db *gorm.DB) *CatalogHandler {
	return &CatalogHandler{
		sugar: l,
		db:    db,
	}
}

func (h *CatalogHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.GET("/:id/back-matter", h.GetBackMatter)
	//api.POST("", h.Create)
	//api.PUT("/:id", h.Update)
	//api.DELETE("/:id", h.Delete)
}

// List godoc
//
//	@Summary		List catalogs
//	@Description	Retrieves all catalogs.
//	@Tags			Oscal Catalogs
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscal.List.responseCatalog]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/catalogs [get]
func (h *CatalogHandler) List(ctx echo.Context) error {
	type responseCatalog struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	var catalogs []relational.Catalog
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Find(&catalogs).Error; err != nil {
		h.sugar.Warnw("Failed to load catalogs", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalCatalogs := []oscalTypes_1_1_3.Catalog{}
	for _, catalog := range catalogs {
		oscalCatalogs = append(oscalCatalogs, *catalog.MarshalOscal())
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Catalog]{Data: oscalCatalogs})
}

// Get godoc
//
//	@Summary		Get a Catalog
//	@Description	Retrieves a single Catalog by its unique ID.
//	@Tags			Oscal Catalogs
//	@Produce		json
//	@Param			id	path		string	true	"Catalog ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscal.Get.responseCatalog]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/catalogs/{id} [get]
func (h *CatalogHandler) Get(ctx echo.Context) error {
	type responseCatalog struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var catalog relational.Catalog
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		First(&catalog, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]{Data: *catalog.MarshalOscal()})
}

// GetBackMatter godoc
//
//	@Summary		Get back-matter for a Catalog
//	@Description	Retrieves the back-matter for a given Catalog.
//	@Tags			Oscal Catalogs
//	@Produce		json
//	@Param			id	path		string	true	"Catalog ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/catalogs/{id}/back-matter [get]
func (h *CatalogHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var catalog relational.Catalog
	if err := h.db.
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		First(&catalog, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	//handler.GenericDataResponse[struct {
	//			UUID     uuid.UUID           `json:"uuid"`
	//			Metadata relational.Metadata `json:"metadata"`
	//		}]{}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.BackMatter]{Data: catalog.BackMatter.MarshalOscal()})
}

//
//func (h *CatalogHandler) Create(ctx echo.Context) error {
//	var catalog relational.Catalog
//	if err := ctx.Bind(&catalog); err != nil {
//		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
//	}
//	if err := h.catalogService.CreateCatalog(&catalog); err != nil {
//		h.sugar.Errorw("Failed to create catalog", "error", err)
//		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
//	}
//	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[relational.Catalog]{Data: catalog})
//}
//
//func (h *CatalogHandler) Update(ctx echo.Context) error {
//	idParam := ctx.Param("id")
//	id, err := uuid.Parse(idParam)
//	if err != nil {
//		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
//		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
//	}
//	var catalog relational.Catalog
//	if err := ctx.Bind(&catalog); err != nil {
//		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
//	}
//	// Enforce the URL ID
//	catalog.ID = &id
//	if err := h.catalogService.UpdateCatalog(&catalog); err != nil {
//		h.sugar.Errorw("Failed to update catalog", "id", id, "error", err)
//		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
//	}
//	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.Catalog]{Data: catalog})
//}
//
//func (h *CatalogHandler) Delete(ctx echo.Context) error {
//	idParam := ctx.Param("id")
//	id, err := uuid.Parse(idParam)
//	if err != nil {
//		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
//		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
//	}
//	if err := h.catalogService.DeleteCatalog(id); err != nil {
//		h.sugar.Errorw("Failed to delete catalog", "id", id, "error", err)
//		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
//	}
//	return ctx.NoContent(http.StatusNoContent)
//}
