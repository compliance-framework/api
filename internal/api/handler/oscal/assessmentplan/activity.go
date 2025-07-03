package assessmentplan

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// validateActivityInput validates activity input
func (h *AssessmentPlanHandler) validateActivityInput(activity *oscalTypes_1_1_3.Activity) error {
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

// GetActivities godoc
//
//	@Summary		Get Assessment Plan Activities
//	@Description	Retrieves all activities for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[[]oscalTypes_1_1_3.Activity]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/activities [get]
func (h *AssessmentPlanHandler) GetActivities(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	// Get activities through tasks
	var activities []relational.Activity
	if err := h.db.Joins("JOIN associated_activities ON activities.id = associated_activities.activity_id").
		Joins("JOIN tasks ON associated_activities.task_id = tasks.id").
		Where("tasks.parent_id = ? AND tasks.parent_type = ?", id, "AssessmentPlan").
		Find(&activities).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve activities: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalActivities := make([]*oscalTypes_1_1_3.Activity, len(activities))
	for i, activity := range activities {
		oscalActivities[i] = activity.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[[]*oscalTypes_1_1_3.Activity]{Data: oscalActivities})
}

// CreateActivity godoc
//
//	@Summary		Create Assessment Plan Activity
//	@Description	Creates a new activity for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Plan ID"
//	@Param			activity	body		oscalTypes_1_1_3.Activity	true	"Activity object"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Activity]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/activities [post]
func (h *AssessmentPlanHandler) CreateActivity(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
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

	// Save to database
	if err := h.db.Create(relationalActivity).Error; err != nil {
		h.sugar.Errorf("Failed to create activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]{Data: relationalActivity.MarshalOscal()})
}

// UpdateActivity godoc
//
//	@Summary		Update Assessment Plan Activity
//	@Description	Updates an existing activity for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Plan ID"
//	@Param			activityId	path		string						true	"Activity ID"
//	@Param			activity	body		oscalTypes_1_1_3.Activity	true	"Activity object"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Activity]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/activities/{activityId} [put]
func (h *AssessmentPlanHandler) UpdateActivity(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	activityIdParam := ctx.Param("activityId")
	activityId, err := uuid.Parse(activityIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid activity id", "activityId", activityIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
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
	relationalActivity.ID = &activityId

	// Update in database
	if err := h.db.Where("id = ?", activityId).Updates(relationalActivity).Error; err != nil {
		h.sugar.Errorf("Failed to update activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]{Data: relationalActivity.MarshalOscal()})
}

// DeleteActivity godoc
//
//	@Summary		Delete Assessment Plan Activity
//	@Description	Deletes an activity from an Assessment Plan.
//	@Tags			Assessment Plans
//	@Param			id			path	string	true	"Assessment Plan ID"
//	@Param			activityId	path	string	true	"Activity ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/activities/{activityId} [delete]
func (h *AssessmentPlanHandler) DeleteActivity(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	activityIdParam := ctx.Param("activityId")
	activityId, err := uuid.Parse(activityIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid activity id", "activityId", activityIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	// Delete activity
	if err := h.db.Where("id = ?", activityId).Delete(&relational.Activity{}).Error; err != nil {
		h.sugar.Errorf("Failed to delete activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}
