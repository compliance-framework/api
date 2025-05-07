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
	api.GET("/:id/groups", h.GetGroups)
	api.GET("/:id/groups/:group", h.GetGroup)
	api.GET("/:id/groups/:group/groups", h.GetSubGroups)
	api.GET("/:id/groups/:group/controls", h.GetGroupControls)
	api.GET("/:id/controls", h.GetControls)
	api.GET("/:id/controls/:control", h.GetControl)
	api.GET("/:id/controls/:control/controls", h.GetSubControls)
}

// List godoc
//
//	@Summary		List catalogs
//	@Description	Retrieves all catalogs.
//	@Tags			Oscal
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
//	@Tags			Oscal
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
//	@Tags			Oscal
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

// GetGroup godoc
//
//	@Summary		Get a specific Group within a Catalog
//	@Description	Retrieves a single Group by its ID for a given Catalog.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id		path		string	true	"Catalog ID"
//	@Param			group	path		string	true	"Group ID"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Group]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups/{group} [get]
func (h *CatalogHandler) GetGroup(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	groupID := ctx.Param("group")
	var group relational.Group
	if err := h.db.
		Where("id = ? AND catalog_id = ?", groupID, id).
		First(&group).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog group", "catalog_id", idParam, "group_id", groupID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Group]{Data: *group.MarshalOscal()})
}

// GetGroups godoc
//
//	@Summary		List groups for a Catalog
//	@Description	Retrieves the top-level groups for a given Catalog.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Catalog ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Group]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups [get]
func (h *CatalogHandler) GetGroups(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var catalog relational.Catalog
	if err := h.db.
		Preload("Groups").
		First(&catalog, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog groups", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalGroups := make([]oscalTypes_1_1_3.Group, len(catalog.Groups))
	for i, group := range catalog.Groups {
		oscalGroups[i] = *group.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Group]{Data: oscalGroups})
}

// GetSubGroups godoc
//
//	@Summary		List sub-groups for a Group within a Catalog
//	@Description	Retrieves the sub-groups of a specific Group in a given Catalog.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id		path		string	true	"Catalog ID"
//	@Param			group	path		string	true	"Group ID"
//	@Success		200		{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Group]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups/{group}/groups [get]
func (h *CatalogHandler) GetSubGroups(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	groupID := ctx.Param("group")
	var group relational.Group
	if err := h.db.
		Preload("Groups").
		Where("id = ? AND catalog_id = ?", groupID, id).
		First(&group).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load subgroup list", "catalog_id", idParam, "group_id", groupID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalGroups := make([]oscalTypes_1_1_3.Group, len(group.Groups))
	for i, sg := range group.Groups {
		oscalGroups[i] = *sg.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Group]{Data: oscalGroups})
}

// GetGroupControls godoc
//
//	@Summary		List controls for a Group within a Catalog
//	@Description	Retrieves the controls directly under a specific Group in a given Catalog.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id		path		string	true	"Catalog ID"
//	@Param			group	path		string	true	"Group ID"
//	@Success		200		{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Control]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups/{group}/controls [get]
func (h *CatalogHandler) GetGroupControls(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	groupID := ctx.Param("group")
	var group relational.Group
	if err := h.db.
		Preload("Controls").
		Where("id = ? AND catalog_id = ?", groupID, id).
		First(&group).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load group controls", "catalog_id", idParam, "group_id", groupID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalControls := make([]oscalTypes_1_1_3.Control, len(group.Controls))
	for i, ctl := range group.Controls {
		oscalControls[i] = *ctl.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Control]{Data: oscalControls})
}

// GetControl godoc
//
//	@Summary		Get a specific Control within a Catalog
//	@Description	Retrieves a single Control by its ID for a given Catalog.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id		path		string	true	"Catalog ID"
//	@Param			control	path		string	true	"Control ID"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Control]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/controls/{control} [get]
func (h *CatalogHandler) GetControl(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	controlID := ctx.Param("control")
	var control relational.Control
	if err := h.db.
		Where("id = ? AND catalog_id = ?", controlID, id).
		First(&control).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog control", "catalog_id", idParam, "control_id", controlID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Control]{Data: *control.MarshalOscal()})
}

// GetControls godoc
//
//	@Summary		List controls for a Catalog
//	@Description	Retrieves the top-level controls for a given Catalog.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Catalog ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Control]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/catalogs/{id}/controls [get]
func (h *CatalogHandler) GetControls(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var catalog relational.Catalog
	if err := h.db.
		Preload("Controls").
		First(&catalog, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog controls", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalControls := make([]oscalTypes_1_1_3.Control, len(catalog.Controls))
	for i, ctl := range catalog.Controls {
		oscalControls[i] = *ctl.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Control]{Data: oscalControls})
}

// GetSubControls godoc
//
//	@Summary		List child controls for a Control within a Catalog
//	@Description	Retrieves the controls directly under a specific Control in a given Catalog.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id		path		string	true	"Catalog ID"
//	@Param			control	path		string	true	"Control ID"
//	@Success		200		{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Control]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/controls/{control}/controls [get]
func (h *CatalogHandler) GetSubControls(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	controlID := ctx.Param("control")
	var control relational.Control
	if err := h.db.
		Preload("Controls").
		Where("id = ? AND catalog_id = ?", controlID, id).
		First(&control).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load sub-controls list", "catalog_id", idParam, "control_id", controlID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalControls := make([]oscalTypes_1_1_3.Control, len(control.Controls))
	for i, ctl := range control.Controls {
		oscalControls[i] = *ctl.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Control]{Data: oscalControls})
}
