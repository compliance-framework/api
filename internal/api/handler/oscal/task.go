package oscal

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// TODO[onakin]: Tasks can also be parented by other domain models - even other Tasks
// So we should have a proper Service or UseCases layer where we handle these relations
// Keeping AssessmentPlan specific Task endpoints here for now

// validateTaskInput validates task input
func (h *AssessmentPlanHandler) validateTaskInput(task *oscalTypes_1_1_3.Task) error {
	if task.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(task.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if task.Title == "" {
		return fmt.Errorf("title is required")
	}
	if task.Type == "" {
		return fmt.Errorf("type is required")
	}
	return nil
}

// GetTasks godoc
//
//	@Summary		Get Assessment Plan Tasks
//	@Description	Retrieves all tasks for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[[]oscalTypes_1_1_3.Task]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks [get]
func (h *AssessmentPlanHandler) GetTasks(ctx echo.Context) error {
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

	var tasks []relational.Task
	if err := h.db.
		Preload("Dependencies").
		Where("parent_id = ? AND parent_type = ?", id, "assessment_plans").
		Find(&tasks).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve tasks: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalTasks := make([]*oscalTypes_1_1_3.Task, len(tasks))
	for i, task := range tasks {
		oscalTasks[i] = task.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[[]*oscalTypes_1_1_3.Task]{Data: oscalTasks})
}

// CreateTask godoc
//
//	@Summary		Create Assessment Plan Task
//	@Description	Creates a new task for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Assessment Plan ID"
//	@Param			task	body		oscalTypes_1_1_3.Task	true	"Task object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Task]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks [post]
func (h *AssessmentPlanHandler) CreateTask(ctx echo.Context) error {
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

	var task oscalTypes_1_1_3.Task
	if err := ctx.Bind(&task); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateTaskInput(&task); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relationalTask := &relational.Task{}
	relationalTask.UnmarshalOscal(task)
	relationalTask.ParentID = &id
	relationalTask.ParentType = "assessment_plans"

	// Save to database
	if err := h.db.Create(relationalTask).Error; err != nil {
		h.sugar.Errorf("Failed to create task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[*oscalTypes_1_1_3.Task]{Data: relationalTask.MarshalOscal()})
}

// UpdateTask godoc
//
//	@Summary		Update Assessment Plan Task
//	@Description	Updates an existing task for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Assessment Plan ID"
//	@Param			taskId	path		string					true	"Task ID"
//	@Param			task	body		oscalTypes_1_1_3.Task	true	"Task object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Task]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks/{taskId} [put]
func (h *AssessmentPlanHandler) UpdateTask(ctx echo.Context) error {
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

	var task oscalTypes_1_1_3.Task
	if err := ctx.Bind(&task); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateTaskInput(&task); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relationalTask := &relational.Task{}
	relationalTask.UnmarshalOscal(task)
	relationalTask.ID = &taskId
	relationalTask.ParentID = &id
	relationalTask.ParentType = "assessment_plans"

	// Load the existing task first
	var existingTask relational.Task
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", taskId, id, "assessment_plans").First(&existingTask).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Task not found for update", "taskId", taskId, "planId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("task with id %s not found in plan %s", taskId, id)))
		}
		h.sugar.Errorf("Failed to load existing task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Replace the dependencies association using GORM's Association API
	if err := h.db.Model(&existingTask).Association("Dependencies").Replace(relationalTask.Dependencies); err != nil {
		h.sugar.Errorf("Failed to update task dependencies: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update other task fields (excluding dependencies which were handled above)
	updateData := map[string]any{
		"type":        relationalTask.Type,
		"title":       relationalTask.Title,
		"description": relationalTask.Description,
		"remarks":     relationalTask.Remarks,
		"props":       relationalTask.Props,
		"links":       relationalTask.Links,
		"timing":      relationalTask.Timing,
	}

	if err := h.db.Model(&existingTask).Updates(updateData).Error; err != nil {
		h.sugar.Errorf("Failed to update task fields: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Handle ResponsibleRole association if needed
	if err := h.db.Model(&existingTask).Association("ResponsibleRole").Replace(relationalTask.ResponsibleRole); err != nil {
		h.sugar.Errorf("Failed to update task responsible roles: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Reload the task with all associations to return the updated data
	var updatedTask relational.Task
	if err := h.db.Preload("Dependencies").Preload("ResponsibleRole").Where("id = ?", taskId).First(&updatedTask).Error; err != nil {
		h.sugar.Errorf("Failed to reload updated task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Task]{Data: updatedTask.MarshalOscal()})
}

// DeleteTask godoc
//
//	@Summary		Delete Assessment Plan Task
//	@Description	Deletes a task from an Assessment Plan.
//	@Tags			Assessment Plans
//	@Param			id		path	string	true	"Assessment Plan ID"
//	@Param			taskId	path	string	true	"Task ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks/{taskId} [delete]
func (h *AssessmentPlanHandler) DeleteTask(ctx echo.Context) error {
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

	// Delete task and check if resource exists
	result := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", taskId, id, "assessment_plans").Delete(&relational.Task{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete task: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the task was found and deleted
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Task not found for deletion", "taskId", taskId, "planId", id)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("task with id %s not found in plan %s", taskId, id)))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetTaskActivities godoc
//
//	@Summary		List Associated Activities for a Task
//	@Description	Retrieves all Activities associated with a specific Task in an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id		path		string	true	"Assessment Plan ID"
//	@Param			taskId	path		string	true	"Task ID"
//	@Success		200		{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.AssociatedActivity]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks/{taskId}/associated-activities [get]
func (h *AssessmentPlanHandler) GetTaskActivities(ctx echo.Context) error {
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

	var task relational.Task
	if err := h.db.
		Preload("AssociatedActivities").
		Preload("AssociatedActivities.Activity").
		First(&task, "id = ?", taskId).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve tasks: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	associatedActivities := make([]*oscalTypes_1_1_3.AssociatedActivity, len(task.AssociatedActivities))
	for i, activity := range task.AssociatedActivities {
		associatedActivities[i] = activity.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.AssociatedActivity]{Data: associatedActivities})
}

// AssociateTaskActivity godoc
//
//	@Summary		Associate an Activity with a Task
//	@Description	Associates an existing Activity to a Task within an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id			path	string	true	"Assessment Plan ID"
//	@Param			taskId		path	string	true	"Task ID"
//	@Param			activityId	path	string	true	"Activity ID"
//	@Success		200			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks/{taskId}/associated-activities/{activityId} [post]
func (h *AssessmentPlanHandler) AssociateTaskActivity(ctx echo.Context) error {
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

	taskIdParam := ctx.Param("taskId")
	taskId, err := uuid.Parse(taskIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid task id", "taskId", taskIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	activityIdParam := ctx.Param("activityId")
	activityId, err := uuid.Parse(activityIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid activity id", "activityId", activityIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify task exists and belongs to the assessment plan
	var task relational.Task
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", taskId, id, "assessment_plans").First(&task).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Task not found in assessment plan", "taskId", taskId, "planId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("task with id %s not found in assessment plan %s", taskId, id)))
		}
		h.sugar.Errorf("Failed to retrieve task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err = h.db.Model(task).Association("AssociatedActivities").Append(&relational.AssociatedActivity{
		Activity: relational.Activity{
			UUIDModel: relational.UUIDModel{
				ID: &activityId,
			},
		},
	}); err != nil {
		h.sugar.Errorf("Failed to associate activity with task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusOK)
}

// DisassociateTaskActivity godoc
//
//	@Summary		Disassociate an Activity from a Task
//	@Description	Removes an association of an Activity from a Task within an Assessment Plan.
//	@Tags			Assessment Plans
//	@Param			id			path	string	true	"Assessment Plan ID"
//	@Param			taskId		path	string	true	"Task ID"
//	@Param			activityId	path	string	true	"Activity ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id}/tasks/{taskId}/associated-activities/{activityId} [delete]
func (h *AssessmentPlanHandler) DisassociateTaskActivity(ctx echo.Context) error {
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

	taskParam := ctx.Param("taskId")
	taskId, err := uuid.Parse(taskParam)
	if err != nil {
		h.sugar.Warnw("Invalid task id", "id", taskId, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	activityIdParam := ctx.Param("activityId")
	activityId, err := uuid.Parse(activityIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid activity id", "activityId", activityIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err = h.db.Where("task_id = ? AND activity_id = ?", taskId, activityId).Delete(&relational.AssociatedActivity{}).Error; err != nil {
		h.sugar.Errorf("Failed to delete associated activity: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}
