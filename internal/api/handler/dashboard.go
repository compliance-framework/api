package handler

import (
	"errors"
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"net/http"
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
	api.GET("/compliance-by-control/:id", h.ComplianceByControl)
	api.POST("", h.Create)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
}

type DashboardWithControlsResponse struct {
	relational.Dashboard
	Controls []oscalTypes_1_1_3.Control `json:"controls"`
}

// Get godoc
//
//	@Summary		Get a dashboard
//	@Description	Retrieves a single dashboard by its unique ID.
//	@Tags			Dashboards
//	@Produce		json
//	@Param			id	path		string	true	"Dashboard ID"
//	@Success		200	{object}	GenericDataResponse[DashboardWithControlsResponse]
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

	var dashboard relational.Dashboard
	if err := h.db.Preload("Controls").First(&dashboard, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := DashboardWithControlsResponse{
		Dashboard: dashboard,
		Controls: func() []oscalTypes_1_1_3.Control {
			result := []oscalTypes_1_1_3.Control{}
			for _, control := range dashboard.Controls {
				result = append(result, *control.MarshalOscal())
			}
			return result
		}(),
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[DashboardWithControlsResponse]{Data: response})
}

// List godoc
//
//	@Summary		List dashboards
//	@Description	Retrieves all dashboards.
//	@Tags			Dashboards
//	@Produce		json
//	@Success		200	{object}	GenericDataListResponse[DashboardWithControlsResponse]
//	@Failure		500	{object}	api.Error
//	@Router			/dashboards [get]
func (h *DashboardHandler) List(ctx echo.Context) error {
	var dashboards []relational.Dashboard
	if err := h.db.Preload("Controls").Find(&dashboards).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := func() []DashboardWithControlsResponse {
		result := []DashboardWithControlsResponse{}
		for _, dashboard := range dashboards {
			result = append(result, DashboardWithControlsResponse{
				Dashboard: dashboard,
				Controls: func() []oscalTypes_1_1_3.Control {
					result := []oscalTypes_1_1_3.Control{}
					for _, control := range dashboard.Controls {
						result = append(result, *control.MarshalOscal())
					}
					return result
				}(),
			})
		}
		return result
	}()

	return ctx.JSON(http.StatusOK, GenericDataListResponse[DashboardWithControlsResponse]{Data: response})
}

// ComplianceByControl godoc
//
//	@Summary		Get compliance counts by control
//	@Description	Retrieves the count of evidence statuses for dashboards associated with a specific Control ID.
//	@Tags			Dashboards
//	@Produce		json
//	@Param			id	path		string	true	"Control ID"
//	@Success		200	{object}	GenericDataListResponse[handler.ComplianceByControl.StatusCount]
//	@Failure		500	{object}	api.Error
//	@Router			/dashboards/compliance-by-control/{id} [get]
func (h *DashboardHandler) ComplianceByControl(ctx echo.Context) error {
	id := ctx.Param("id")
	control := &relational.Control{}
	if err := h.db.Preload("Dashboards").First(control, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	filters := []labelfilter.Filter{}
	for _, dashboard := range control.Dashboards {
		filters = append(filters, dashboard.Filter.Data())
	}

	type StatusCount struct {
		Count  int64  `json:"count"`
		Status string `json:"status"`
	}

	if len(filters) == 0 {
		// If there are no filters assigned for the control, we should return nothing explicitly, otherwise we return everything implicitly
		return ctx.JSON(http.StatusOK, GenericDataListResponse[StatusCount]{Data: []StatusCount{}})
	}

	latestQuery := h.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, h.db, filters...)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	rows := []StatusCount{}
	if err := q.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[StatusCount]{Data: rows})
}

// Create godoc
//
//	@Summary		Create a new dashboard
//	@Description	Creates a new dashboard.
//	@Tags			Dashboards
//	@Accept			json
//	@Produce		json
//	@Param			dashboard	body		createDashboardRequest	true	"Dashboard to add"
//	@Success		201			{object}	GenericDataResponse[relational.Dashboard]
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

	dashboard := relational.Dashboard{
		Name:   req.Name,
		Filter: datatypes.NewJSONType(req.Filter),
	}

	if req.Controls != nil {
		for _, controlId := range *req.Controls {
			searchDB := h.db.Session(&gorm.Session{})
			control := relational.Control{}
			err := searchDB.First(&control, "id = ?", controlId).Error
			if err != nil {
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			dashboard.Controls = append(dashboard.Controls, control)
		}
	}

	if err := h.db.Create(&dashboard).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[relational.Dashboard]{Data: dashboard})
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
//	@Success		200			{object}	GenericDataResponse[relational.Dashboard]
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

	var dashboard relational.Dashboard
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

	return ctx.JSON(http.StatusOK, GenericDataResponse[relational.Dashboard]{Data: dashboard})
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

	var dashboard relational.Dashboard
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
