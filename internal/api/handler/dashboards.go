package handler

import (
	"errors"
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// DashboardHandler handles CRUD operations for dashboards.
type DashboardHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func NewDashboardHandler(sugar *zap.SugaredLogger, db *gorm.DB) *DashboardHandler {
	return &DashboardHandler{
		sugar: sugar,
		db:    db,
	}
}

// Register registers the dashboard endpoints.
func (h *DashboardHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.POST("", h.Create)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
}

// Get godoc
//
//	@Summary		Get a dashboard
//	@Description	Retrieves a single dashboard by its unique ID.
//	@Tags			Dashboards
//	@Produce		json
//	@Param			id	path		string	true	"Dashboard ID"
//	@Success		200	{object}	GenericDataResponse[service.Dashboard]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/dashboards/{id} [get]
func (h *DashboardHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid dashboard id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var dashboard service.Dashboard
	if err := h.db.First(&dashboard, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[service.Dashboard]{Data: dashboard})
}

// List godoc
//
//	@Summary		List dashboards
//	@Description	Retrieves all dashboards.
//	@Tags			Dashboards
//	@Produce		json
//	@Success		200	{object}	GenericDataListResponse[service.Dashboard]
//	@Failure		500	{object}	api.Error
//	@Router			/dashboards [get]
func (h *DashboardHandler) List(ctx echo.Context) error {
	var dashboards []service.Dashboard
	if err := h.db.Find(&dashboards).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[service.Dashboard]{Data: dashboards})
}

// Create godoc
//
//	@Summary		Create a new dashboard
//	@Description	Creates a new dashboard.
//	@Tags			Dashboards
//	@Accept			json
//	@Produce		json
//	@Param			dashboard	body		createDashboardRequest	true	"Dashboard to add"
//	@Success		201			{object}	GenericDataResponse[service.Dashboard]
//	@Failure		400			{object}	api.Error
//	@Failure		422			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/dashboards [post]
func (h *DashboardHandler) Create(ctx echo.Context) error {
	var req createDashboardRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	dashboard := service.Dashboard{
		Name:   req.Name,
		Filter: datatypes.NewJSONType(req.Filter),
	}

	if err := h.db.Create(&dashboard).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[service.Dashboard]{Data: dashboard})
}

// Update godoc
//
//	@Summary		Update a dashboard
//	@Description	Updates an existing dashboard.
//	@Tags			Dashboards
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"Dashboard ID"
//	@Param			dashboard	body		createDashboardRequest	true	"Dashboard to update"
//	@Success		200			{object}	GenericDataResponse[service.Dashboard]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/dashboards/{id} [put]
func (h *DashboardHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid dashboard id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req createDashboardRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	var dashboard service.Dashboard
	if err := h.db.First(&dashboard, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	dashboard.Name = req.Name
	dashboard.Filter = datatypes.NewJSONType(req.Filter)

	if err := h.db.Save(&dashboard).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[service.Dashboard]{Data: dashboard})
}

// Delete godoc
//
//	@Summary		Delete a dashboard
//	@Description	Deletes a dashboard.
//	@Tags			Dashboards
//	@Param			id	path	string	true	"Dashboard ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/dashboards/{id} [delete]
func (h *DashboardHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid dashboard id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var dashboard service.Dashboard
	if err := h.db.First(&dashboard, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Delete(&dashboard).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}
