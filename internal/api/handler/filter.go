package handler

import (
	"errors"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// FilterHandler handles CRUD operations for filters.
type FilterHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func NewFilterHandler(sugar *zap.SugaredLogger, db *gorm.DB) *FilterHandler {
	return &FilterHandler{
		sugar: sugar,
		db:    db,
	}
}

// Register registers the filter endpoints.
func (h *FilterHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.POST("", h.Create)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
}

type FilterWithControlsAndComponentsResponse struct {
	relational.Filter
	Controls   []oscalTypes_1_1_3.Control          `json:"controls"`
	Components []oscalTypes_1_1_3.DefinedComponent `json:"components"`
}

// Get godoc
//
//	@Summary		Get a filter
//	@Description	Retrieves a single filter by its unique ID.
//	@Tags			Filters
//	@Produce		json
//	@Param			id	path		string	true	"Filter ID"
//	@Success		200	{object}	GenericDataResponse[FilterWithControlsAndComponentsResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/filters/{id} [get]
func (h *FilterHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid filter id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var filter relational.Filter
	if err := h.db.Preload("Controls").First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := FilterWithControlsAndComponentsResponse{
		Filter: filter,
		Controls: func() []oscalTypes_1_1_3.Control {
			result := []oscalTypes_1_1_3.Control{}
			for _, control := range filter.Controls {
				result = append(result, *control.MarshalOscal())
			}
			return result
		}(),
		Components: func() []oscalTypes_1_1_3.DefinedComponent {
			result := []oscalTypes_1_1_3.DefinedComponent{}
			for _, component := range filter.Components {
				result = append(result, *component.MarshalOscal())
			}
			return result
		}(),
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[FilterWithControlsAndComponentsResponse]{Data: response})
}

// List godoc
//
//	@Summary		List filters
//	@Description	Retrieves all filters.
//	@Tags			Filters
//	@Produce		json
//	@Success		200	{object}	GenericDataListResponse[FilterWithControlsAndComponentsResponse]
//	@Failure		500	{object}	api.Error
//	@Router			/filters [get]
func (h *FilterHandler) List(ctx echo.Context) error {
	controlID := ctx.QueryParam("controlId")
	componentID := ctx.QueryParam("componentId")

	query := h.db.Model(&relational.Filter{}).Preload("Controls").Preload("Components")

	if controlID != "" && componentID == "" {
		query = query.
			Joins("JOIN filter_controls ON filter_controls.filter_id = filters.id").
			Joins("JOIN controls ON controls.catalog_id = filter_controls.control_catalog_id::uuid AND controls.id = filter_controls.control_id").
			Where("controls.id = ?", controlID).
			Distinct()
	}

	if controlID == "" && componentID != "" {
		query = query.
			Joins("JOIN filter_defined_components ON filter_defined_components.filter_id = filters.id").
			Joins("JOIN defined_components ON defined_components.id = filter_defined_components.defined_component_id").
			Where("defined_components.id = ?", componentID).
			Distinct()
	}

	if controlID != "" && componentID != "" {
		query = query.
			Joins("JOIN filter_controls ON filter_controls.filter_id = filters.id").
			Joins("JOIN controls ON controls.catalog_id = filter_controls.control_catalog_id::uuid AND controls.id = filter_controls.control_id").
			Joins("JOIN filter_defined_components ON filter_defined_components.filter_id = filters.id").
			Joins("JOIN defined_components ON defined_components.id = filter_defined_components.defined_component_id").
			Where("controls.id = ? AND defined_components.id = ?", controlID, componentID).
			Distinct()
	}

	var filters []relational.Filter
	if err := query.Find(&filters).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := func() []FilterWithControlsAndComponentsResponse {
		result := []FilterWithControlsAndComponentsResponse{}
		for _, filter := range filters {
			result = append(result, FilterWithControlsAndComponentsResponse{
				Filter: filter,
				Controls: func() []oscalTypes_1_1_3.Control {
					result := []oscalTypes_1_1_3.Control{}
					for _, control := range filter.Controls {
						result = append(result, *control.MarshalOscal())
					}
					return result
				}(),
				Components: func() []oscalTypes_1_1_3.DefinedComponent {
					result := []oscalTypes_1_1_3.DefinedComponent{}
					for _, component := range filter.Components {
						result = append(result, *component.MarshalOscal())
					}
					return result
				}(),
			})
		}
		return result
	}()

	return ctx.JSON(http.StatusOK, GenericDataListResponse[FilterWithControlsAndComponentsResponse]{Data: response})
}

// Create godoc
//
//	@Summary		Create a new filter
//	@Description	Creates a new filter.
//	@Tags			Filters
//	@Accept			json
//	@Produce		json
//	@Param			filter	body		createFilterRequest	true	"Filter to add"
//	@Success		201		{object}	GenericDataResponse[relational.Filter]
//	@Failure		400		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/filters [post]
func (h *FilterHandler) Create(ctx echo.Context) error {
	var req createFilterRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	filter := relational.Filter{
		Name:   req.Name,
		Filter: datatypes.NewJSONType(req.Filter),
	}

	if req.Controls != nil {
		for _, controlId := range *req.Controls {
			searchDB := h.db.Session(&gorm.Session{})
			control := relational.Control{}
			err := searchDB.First(&control, "id = ?", controlId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Controls = append(filter.Controls, control)
		}
	}

	if req.Components != nil {
		for _, componentId := range *req.Components {
			searchDB := h.db.Session(&gorm.Session{})
			component := relational.DefinedComponent{}
			err := searchDB.First(&component, "id = ?", componentId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Components = append(filter.Components, component)
		}
	}

	if err := h.db.Create(&filter).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[relational.Filter]{Data: filter})
}

// Update godoc
//
//	@Summary		Update a filter
//	@Description	Updates an existing filter.
//	@Tags			Filters
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Filter ID"
//	@Param			filter	body		createFilterRequest	true	"Filter to update"
//	@Success		200		{object}	GenericDataResponse[relational.Filter]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/filters/{id} [put]
func (h *FilterHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid filter id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req createFilterRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	var filter relational.Filter
	if err := h.db.First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	filter.Name = req.Name
	filter.Filter = datatypes.NewJSONType(req.Filter)

	// Update controls if provided
	if req.Controls != nil {
		// Clear existing controls association
		if err := h.db.Model(&filter).Association("Controls").Clear(); err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		// Add new controls
		for _, controlId := range *req.Controls {
			searchDB := h.db.Session(&gorm.Session{})
			control := relational.Control{}
			err := searchDB.First(&control, "id = ?", controlId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Controls = append(filter.Controls, control)
		}
	}

	if req.Components != nil {
		if err := h.db.Model(&filter).Association("Components").Clear(); err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		for _, componentId := range *req.Components {
			searchDB := h.db.Session(&gorm.Session{})
			component := relational.DefinedComponent{}
			err := searchDB.First(&component, "id = ?", componentId).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ctx.JSON(http.StatusNotFound, api.NewError(err))
				}
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			filter.Components = append(filter.Components, component)
		}
	}

	if err := h.db.Save(&filter).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[relational.Filter]{Data: filter})
}

// Delete godoc
//
//	@Summary		Delete a filter
//	@Description	Deletes a filter.
//	@Tags			Filters
//	@Param			id	path	string	true	"Filter ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/filters/{id} [delete]
func (h *FilterHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid filter id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var filter relational.Filter
	if err := h.db.First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Delete(&filter).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}
