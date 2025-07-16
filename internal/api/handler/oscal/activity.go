package oscal

import (
	"fmt"
	"go.uber.org/zap"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

type ActivityHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewActivityHandler(sugar *zap.SugaredLogger, db *gorm.DB) *ActivityHandler {
	return &ActivityHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *ActivityHandler) Register(api *echo.Group) {
	// Activities sub-resource management
	api.POST("", h.CreateActivity)
	api.GET("/:id", h.GetActivity)
	api.PUT("/:id", h.UpdateActivity)
	api.DELETE("/:id", h.DeleteActivity)
}

// validateActivityInput validates activity input
func (h *ActivityHandler) validateActivityInput(activity *oscalTypes_1_1_3.Activity) error {
	if activity.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(activity.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if activity.Description == "" {
		return fmt.Errorf("description is required")
	}
	return nil
}

// CreateActivity godoc
//
//	@Summary		Create an Activity
//	@Description	Creates a new activity for us in other resources.
//	@Tags			Activities
//	@Accept			json
//	@Produce		json
//	@Param			activity	body		oscalTypes_1_1_3.Activity	true	"Activity object"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Activity]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/activities [post]
func (h *ActivityHandler) CreateActivity(ctx echo.Context) error {
	var activity oscalTypes_1_1_3.Activity
	if err := ctx.Bind(&activity); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateActivityInput(&activity); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relationalActivity := &relational.Activity{}
	relationalActivity.UnmarshalOscal(activity)

	// Save the activity to database
	if err := h.db.Create(relationalActivity).Error; err != nil {
		h.sugar.Errorf("Failed to create activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]{Data: relationalActivity.MarshalOscal()})
}

// GetActivity godoc
//
//	@Summary		Retrieve an Activity
//	@Description	Retrieves an Activity by its unique ID.
//	@Tags			Activities
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Activity ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Activity]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/activities/{id} [get]
func (h *ActivityHandler) GetActivity(ctx echo.Context) error {
	fmt.Println("Trying to GET activity")
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid activity id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var activity relational.Activity
	if err := h.db.
		Preload("RelatedControls").
		Preload("Steps").
		First(&activity, "id = ?", id).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve tasks: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]{Data: activity.MarshalOscal()})
}

// UpdateActivity godoc
//
//	@Summary		Update an Activity
//	@Description	Updates properties of an existing Activity by its ID.
//	@Tags			Activities
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Activity ID"
//	@Param			activity	body		oscalTypes_1_1_3.Activity	true	"Activity object"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Activity]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/activities/{id} [put]
func (h *ActivityHandler) UpdateActivity(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid activity id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var activity oscalTypes_1_1_3.Activity
	if err := ctx.Bind(&activity); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateActivityInput(&activity); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relationalActivity := &relational.Activity{}
	relationalActivity.UnmarshalOscal(activity)
	relationalActivity.ID = &id

	// Update in database and check if resource exists
	result := h.db.Where("id = ?", id).Updates(relationalActivity)
	if result.Error != nil {
		h.sugar.Errorf("Failed to update activity: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the activity was found and updated
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Activity not found for update", "activityId", id)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("activity with id %s not found", id)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]{Data: relationalActivity.MarshalOscal()})
}

// DeleteActivity godoc
//
//	@Summary		Delete Activity
//	@Description	Deletes an activity
//	@Tags			Activities
//	@Param			id	path	string	true	"Activity ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/activities/{id} [delete]
func (h *ActivityHandler) DeleteActivity(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid activity id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Delete activity and check if resource exists
	result := h.db.Where("id = ?", id).Delete(&relational.Activity{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete activity: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the activity was found and deleted
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Activity not found for deletion", "activityId", id)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("activity with id %s not found", id)))
	}

	return ctx.NoContent(http.StatusNoContent)
}
