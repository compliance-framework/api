package oscal

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

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
//	@Router			/oscal/assessment-plans/{id}/activities [get]
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
//	@Router			/oscal/assessment-plans/{id}/activities [post]
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

	// Start a transaction to ensure consistency
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Save the activity to database
	if err := tx.Create(relationalActivity).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create a task to link this activity to the assessment plan
	task := &relational.Task{
		Type:        "action", // Default type for activity tasks
		Title:       fmt.Sprintf("Task for Activity: %s", activity.UUID),
		Description: &activity.Description,
		ParentID:    &id,
		ParentType:  "AssessmentPlan",
	}

	if err := tx.Create(task).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create task for activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create the associated activity relationship
	associatedActivity := &relational.AssociatedActivity{
		TaskID:     *task.ID,
		ActivityID: *relationalActivity.ID,
		Activity:   *relationalActivity,
	}

	if err := tx.Create(associatedActivity).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create associated activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit activity creation transaction: %v", err)
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
//	@Router			/oscal/assessment-plans/{id}/activities/{activityId} [put]
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

	// Update in database and check if resource exists
	result := h.db.Where("id = ?", activityId).Updates(relationalActivity)
	if result.Error != nil {
		h.sugar.Errorf("Failed to update activity: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the activity was found and updated
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Activity not found for update", "activityId", activityId)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("activity with id %s not found", activityId)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]{Data: relationalActivity.MarshalOscal()})
}

// CreateActivityForTask godoc
//
//	@Summary		Create Activity for Existing Task
//	@Description	Creates a new activity and associates it with an existing task in an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Plan ID"
//	@Param			taskId		path		string						true	"Task ID"
//	@Param			activity	body		oscalTypes_1_1_3.Activity	true	"Activity object"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Activity]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks/{taskId}/activities [post]
func (h *AssessmentPlanHandler) CreateActivityForTask(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	taskIdParam := ctx.Param("taskId")
	taskId, err := uuid.Parse(taskIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid task id", "taskId", taskIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	// Verify task exists and belongs to the assessment plan
	var task relational.Task
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", taskId, id, "AssessmentPlan").First(&task).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Task not found in assessment plan", "taskId", taskId, "planId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("task with id %s not found in assessment plan %s", taskId, id)))
		}
		h.sugar.Errorf("Failed to retrieve task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
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

	// Start a transaction to ensure consistency
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Save the activity to database
	if err := tx.Create(relationalActivity).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create the associated activity relationship
	associatedActivity := &relational.AssociatedActivity{
		TaskID:     taskId,
		ActivityID: *relationalActivity.ID,
		Activity:   *relationalActivity,
	}

	if err := tx.Create(associatedActivity).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create associated activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit activity creation transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]{Data: relationalActivity.MarshalOscal()})
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
//	@Router			/oscal/assessment-plans/{id}/activities/{activityId} [delete]
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

	// Delete activity and check if resource exists
	result := h.db.Where("id = ?", activityId).Delete(&relational.Activity{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete activity: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the activity was found and deleted
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Activity not found for deletion", "activityId", activityId)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("activity with id %s not found", activityId)))
	}

	return ctx.NoContent(http.StatusNoContent)
}
