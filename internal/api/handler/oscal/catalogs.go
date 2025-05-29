package oscal

import (
	"errors"
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"net/http"
	"time"

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
	api.POST("", h.Create)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.GET("/:id/full", h.Full)
	api.GET("/:id/back-matter", h.GetBackMatter)
	api.GET("/:id/groups", h.GetGroups)
	api.POST("/:id/groups", h.CreateGroup)
	api.GET("/:id/groups/:group", h.GetGroup)
	api.PUT("/:id/groups/:group", h.UpdateGroup)
	api.GET("/:id/groups/:group/groups", h.GetGroupSubGroups)
	api.POST("/:id/groups/:group/groups", h.CreateGroupSubGroup)
	api.GET("/:id/groups/:group/controls", h.GetGroupControls)
	api.POST("/:id/groups/:group/controls", h.CreateGroupControl)
	api.GET("/:id/controls", h.GetControls)
	api.POST("/:id/controls", h.CreateControl)
	api.GET("/:id/controls/:control", h.GetControl)
	api.PUT("/:id/controls/:control", h.UpdateControl)
	api.GET("/:id/controls/:control/controls", h.GetControlSubControls)
	api.POST("/:id/controls/:control/controls", h.CreateControlSubControl)
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

// Create godoc
//
//	@Summary		Create a new Catalog
//	@Description	Creates a new OSCAL Catalog.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			catalog	body		oscalTypes_1_1_3.Catalog	true	"Catalog object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs [post]
func (h *CatalogHandler) Create(ctx echo.Context) error {
	now := time.Now()

	var oscalCat oscalTypes_1_1_3.Catalog
	if err := ctx.Bind(&oscalCat); err != nil {
		h.sugar.Warnw("Invalid create catalog request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	relCat := &relational.Catalog{}
	relCat.UnmarshalOscal(oscalCat)
	relCat.Metadata.LastModified = &now
	relCat.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()
	if err := h.db.Create(relCat).Error; err != nil {
		h.sugar.Errorf("Failed to create catalog: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]{Data: *relCat.MarshalOscal()})
}

// Update godoc
//
//	@Summary		Update a Catalog
//	@Description	Updates an existing OSCAL Catalog.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Catalog ID"
//	@Param			catalog	body		oscalTypes_1_1_3.Catalog	true	"Updated Catalog object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id} [put]
func (h *CatalogHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalCat oscalTypes_1_1_3.Catalog
	if err := ctx.Bind(&oscalCat); err != nil {
		h.sugar.Warnw("Invalid update catalog request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	now := time.Now()
	relCat := &relational.Catalog{}
	relCat.UnmarshalOscal(oscalCat)
	relCat.ID = &catalogID
	relCat.Metadata.LastModified = &now
	relCat.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()
	if err := h.db.Model(relCat).Updates(relCat).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to update catalog: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]{Data: *relCat.MarshalOscal()})
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
		Preload("Groups", "parent_id IS NULL").
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

// GetGroupSubGroups godoc
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
func (h *CatalogHandler) GetGroupSubGroups(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	groupID := ctx.Param("group")
	var group relational.Group
	if err := h.db.
		Preload("Groups", "catalog_id = ?", id).
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
		Preload("Controls", "catalog_id = ?", id).
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

// CreateGroup godoc
//
//	@Summary		Create a new Group for a Catalog
//	@Description	Adds a top-level group under the specified Catalog.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Catalog ID"
//	@Param			group	body		oscalTypes_1_1_3.Group	true	"Group object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Group]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups [post]
func (h *CatalogHandler) CreateGroup(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var oscalGroup oscalTypes_1_1_3.Group
	if err := ctx.Bind(&oscalGroup); err != nil {
		h.sugar.Warnw("Invalid create group request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var catalog relational.Catalog
	if err := h.db.
		First(&catalog, "id = ?", catalogID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relGroup := &relational.Group{}
	relGroup.UnmarshalOscal(oscalGroup, catalogID)
	err = h.db.Model(&catalog).Association("Groups").Append(relGroup)
	if err != nil {
		h.sugar.Errorf("Failed to create group: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Group]{Data: *relGroup.MarshalOscal()})
}

// UpdateGroup godoc
//
//	@Summary		Update a Group within a Catalog
//	@Description	Updates the properties of an existing Group under the specified Catalog.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Catalog ID"
//	@Param			group	path		string					true	"Group ID"
//	@Param			group	body		oscalTypes_1_1_3.Group	true	"Updated Group object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Group]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups/{group} [put]
func (h *CatalogHandler) UpdateGroup(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	groupID := ctx.Param("group")
	var oscalGroup oscalTypes_1_1_3.Group
	if err := ctx.Bind(&oscalGroup); err != nil {
		h.sugar.Warnw("Invalid update group request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relGroup := &relational.Group{}
	relGroup.UnmarshalOscal(oscalGroup, catalogID)
	relGroup.ID = groupID
	if err := h.db.Model(relGroup).Updates(relGroup).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to update group: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Group]{Data: *relGroup.MarshalOscal()})
}

// CreateGroupSubGroup godoc
//
//	@Summary		Create a new Sub-Group for a Catalog Group
//	@Description	Adds a sub-group under the specified Catalog and Group.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Catalog ID"
//	@Param			group	path		string					true	"Parent Group ID"
//	@Param			group	body		oscalTypes_1_1_3.Group	true	"Group object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Group]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups/{group}/groups [post]
func (h *CatalogHandler) CreateGroupSubGroup(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalGroup oscalTypes_1_1_3.Group
	if err := ctx.Bind(&oscalGroup); err != nil {
		h.sugar.Warnw("Invalid create sub-group request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	parentGroupID := ctx.Param("group")
	var parent relational.Group
	if err := h.db.
		Where("id = ? AND catalog_id = ?", parentGroupID, catalogID).
		First(&parent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load control", "catalog_id", idParam, "group_id", parentGroupID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relGroup := &relational.Group{}
	relGroup.UnmarshalOscal(oscalGroup, catalogID)
	err = h.db.Model(&parent).Association("Groups").Append(relGroup)
	if err != nil {
		h.sugar.Errorf("Failed to create sub-group: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Group]{Data: *relGroup.MarshalOscal()})
}

// CreateGroupControl godoc
//
//	@Summary		Create a new Control for a Catalog Group
//	@Description	Adds a control under the specified Catalog and Group.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Catalog ID"
//	@Param			group	path		string						true	"Parent Group ID"
//	@Param			control	body		oscalTypes_1_1_3.Control	true	"Control object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Control]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/groups/{group}/controls [post]
func (h *CatalogHandler) CreateGroupControl(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalControl oscalTypes_1_1_3.Control
	if err := ctx.Bind(&oscalControl); err != nil {
		h.sugar.Warnw("Invalid create group control request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	parentGroupID := ctx.Param("group")
	var parent relational.Group
	if err := h.db.
		Where("id = ? AND catalog_id = ?", parentGroupID, catalogID).
		First(&parent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load control", "catalog_id", idParam, "group_id", parentGroupID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relCtl := &relational.Control{}
	relCtl.UnmarshalOscal(oscalControl, catalogID)
	err = h.db.Model(&parent).Association("Controls").Append(relCtl)
	if err != nil {
		h.sugar.Errorf("Failed to create sub-control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Control]{Data: *relCtl.MarshalOscal()})
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
		Preload("Controls", "parent_id IS NULL").
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

// GetControlSubControls godoc
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
func (h *CatalogHandler) GetControlSubControls(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	controlID := ctx.Param("control")
	var control relational.Control
	if err := h.db.
		Preload("Controls", "catalog_id = ?", id).
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

// CreateControl godoc
//
//	@Summary		Create a new Control for a Catalog
//	@Description	Adds a top-level control under the specified Catalog.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Catalog ID"
//	@Param			control	body		oscalTypes_1_1_3.Control	true	"Control object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Control]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/controls [post]
func (h *CatalogHandler) CreateControl(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var oscalControl oscalTypes_1_1_3.Control
	if err := ctx.Bind(&oscalControl); err != nil {
		h.sugar.Warnw("Invalid create control request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var catalog relational.Catalog
	if err := h.db.
		First(&catalog, "id = ?", catalogID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relCtl := &relational.Control{}
	relCtl.UnmarshalOscal(oscalControl, catalogID)
	err = h.db.Model(&catalog).Association("Controls").Append(relCtl)
	if err != nil {
		h.sugar.Errorf("Failed to create sub-control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Control]{Data: *relCtl.MarshalOscal()})
}

// UpdateControl godoc
//
//	@Summary		Update a Control within a Catalog
//	@Description	Updates the properties of an existing Control under the specified Catalog.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Catalog ID"
//	@Param			control	path		string						true	"Control ID"
//	@Param			control	body		oscalTypes_1_1_3.Control	true	"Updated Control object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Control]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/controls/{control} [put]
func (h *CatalogHandler) UpdateControl(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	controlID := ctx.Param("control")
	var oscalControl oscalTypes_1_1_3.Control
	if err := ctx.Bind(&oscalControl); err != nil {
		h.sugar.Warnw("Invalid update control request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relCtl := &relational.Control{}
	relCtl.UnmarshalOscal(oscalControl, catalogID)
	relCtl.ID = controlID
	if err := h.db.Model(relCtl).Updates(relCtl).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to update control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Control]{Data: *relCtl.MarshalOscal()})
}

// CreateControlSubControl godoc
//
//	@Summary		Create a new Sub-Control for a Control within a Catalog
//	@Description	Adds a child control under the specified Catalog Control.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Catalog ID"
//	@Param			control	path		string						true	"Parent Control ID"
//	@Param			control	body		oscalTypes_1_1_3.Control	true	"Control object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Control]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/catalogs/{id}/controls/{control}/controls [post]
func (h *CatalogHandler) CreateControlSubControl(ctx echo.Context) error {
	idParam := ctx.Param("id")
	catalogID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid catalog id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalControl oscalTypes_1_1_3.Control
	if err := ctx.Bind(&oscalControl); err != nil {
		h.sugar.Warnw("Invalid create sub-control request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	parentControlID := ctx.Param("control")
	var parent *relational.Control
	if err := h.db.
		Where("id = ? AND catalog_id = ?", parentControlID, catalogID).
		First(&parent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load control", "catalog_id", idParam, "control_id", parentControlID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relCtl := &relational.Control{}
	relCtl.UnmarshalOscal(oscalControl, catalogID)

	err = h.db.Model(&parent).Association("Controls").Append(relCtl)
	if err != nil {
		h.sugar.Errorf("Failed to create sub-control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Control]{Data: *relCtl.MarshalOscal()})
}

func (h *CatalogHandler) Full(ctx echo.Context) error {
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
		Preload("Controls").
		Preload("Controls.Controls").
		Preload("Groups").
		Preload("Groups.Controls").
		Preload("Groups.Controls.Controls").
		Preload("Groups.Groups").
		Preload("Groups.Groups.Controls").
		Preload("Groups.Groups.Controls.Controls").
		First(&catalog, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load catalog", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]{Data: *catalog.MarshalOscal()})
}
