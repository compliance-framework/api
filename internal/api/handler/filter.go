package handler

import (
	"errors"
	"fmt"
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
	api.POST("/import", h.ImportFilters)
}

type FilterWithAssociations struct {
	relational.Filter
	Controls   []oscalTypes_1_1_3.Control         `json:"controls"`
	Components []oscalTypes_1_1_3.SystemComponent `json:"components"`
}

// Get godoc
//
//	@Summary		Get a filter
//	@Description	Retrieves a single filter by its unique ID.
//	@Tags			Filters
//	@Produce		json
//	@Param			id	path		string	true	"Filter ID"
//	@Success		200	{object}	GenericDataResponse[FilterWithAssociations]
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
	if err := h.db.Preload("Controls").Preload("Components").First(&filter, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := FilterWithAssociations{
		Filter: filter,
		Controls: func() []oscalTypes_1_1_3.Control {
			result := []oscalTypes_1_1_3.Control{}
			for _, control := range filter.Controls {
				result = append(result, *control.MarshalOscal())
			}
			return result
		}(),
		Components: func() []oscalTypes_1_1_3.SystemComponent {
			result := []oscalTypes_1_1_3.SystemComponent{}
			for _, component := range filter.Components {
				result = append(result, *component.MarshalOscal())
			}
			return result
		}(),
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[FilterWithAssociations]{Data: response})
}

// List godoc
//
//	@Summary		List filters
//	@Description	Retrieves all filters, optionally filtered by controlId or componentId.
//	@Tags			Filters
//	@Produce		json
//	@Success		200	{object}	GenericDataListResponse[FilterWithAssociations]
//	@Failure		500	{object}	api.Error
//	@Router			/filters [get]
func (h *FilterHandler) List(ctx echo.Context) error {
	controlID := ctx.QueryParam("controlId")
	componentID := ctx.QueryParam("componentId")

	if controlID != "" && componentID != "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("controlId and componentId are mutually exclusive")))
	}

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
			Joins("JOIN filter_system_components ON filter_system_components.filter_id = filters.id").
			Joins("JOIN system_components ON system_components.id = filter_system_components.system_component_id").
			Where("system_components.id = ?", componentID).
			Distinct()
	}

	var filters []relational.Filter
	if err := query.Find(&filters).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := func() []FilterWithAssociations {
		result := []FilterWithAssociations{}
		for _, filter := range filters {
			result = append(result, FilterWithAssociations{
				Filter: filter,
				Controls: func() []oscalTypes_1_1_3.Control {
					result := []oscalTypes_1_1_3.Control{}
					for _, control := range filter.Controls {
						result = append(result, *control.MarshalOscal())
					}
					return result
				}(),
				Components: func() []oscalTypes_1_1_3.SystemComponent {
					result := []oscalTypes_1_1_3.SystemComponent{}
					for _, component := range filter.Components {
						result = append(result, *component.MarshalOscal())
					}
					return result
				}(),
			})
		}
		return result
	}()

	return ctx.JSON(http.StatusOK, GenericDataListResponse[FilterWithAssociations]{Data: response})
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

	// Filters can be associated with either controls or components, but not both.
	hasControls := req.Controls != nil && len(*req.Controls) > 0
	hasComponents := req.Components != nil && len(*req.Components) > 0

	if hasControls && hasComponents {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("filter Controls and Components fields are mutually exclusive")))
	}

	filter := relational.Filter{
		Name:   req.Name,
		Filter: datatypes.NewJSONType(req.Filter),
	}

	if hasControls {
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

	if hasComponents {
		for _, componentId := range *req.Components {
			searchDB := h.db.Session(&gorm.Session{})
			component := relational.SystemComponent{}
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

	// Note: nil and empty slices are semantically different here.
	// If one of controls / components is present but empty, that
	// means clear the existing controls / components, whereas a nil
	// slice means we should ignore it entirely. Now consider, an
	// existing filter with controls, and a request to update it where
	// controls is nil but components is populated. This should be
	// invalid, as the expected update would be to ignore the controls
	// and update the components, resulting in a filter with both.

	// The request contains one or more of both Controls and Components
	if (req.Controls != nil && len(*req.Controls) > 0) && (req.Components != nil && len(*req.Components) > 0) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf(
				"cannot associate a Filter with both Controls and Components.",
			)),
		)
	}

	// The request contains one or more Controls, with a nil slice for Components
	if (req.Controls != nil && len(*req.Controls) > 0) && (req.Components == nil) && len(filter.Components) > 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf(
				"cannot link Controls to a Filter with associated Components."+
					"To remove existing Component associations, send an empty list for the Components field.",
			)),
		)
	}

	// The request contains a nil slice for Controls, with one or more Components
	if (req.Controls == nil) && (req.Components != nil && len(*req.Components) > 0) && len(filter.Controls) > 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(
			fmt.Errorf(
				"cannot link Components to a Filter with associated Controls."+
					"To remove existing Control associations, send an empty list for the Controls field.",
			)),
		)
	}

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
			component := relational.SystemComponent{}
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
