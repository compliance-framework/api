package assessmentplan

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// validateTaskInput validates task input
func (h *AssessmentPlanHandler) validateTaskInput(task *oscal.Task) error {
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
//	@Success		200	{object}	handler.GenericDataResponse[[]oscal.Task]
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
	if err := h.db.Where("parent_id = ? AND parent_type = ?", id, "AssessmentPlan").Find(&tasks).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve tasks: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalTasks := make([]*oscal.Task, len(tasks))
	for i, task := range tasks {
		oscalTasks[i] = task.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[[]*oscal.Task]{Data: oscalTasks})
}

// CreateTask godoc
//
//	@Summary		Create Assessment Plan Task
//	@Description	Creates a new task for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Assessment Plan ID"
//	@Param			task	body		oscal.Task	true	"Task object"
//	@Success		201		{object}	handler.GenericDataResponse[oscal.Task]
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

	var task oscal.Task
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
	relationalTask.ParentType = "AssessmentPlan"

	// Save to database
	if err := h.db.Create(relationalTask).Error; err != nil {
		h.sugar.Errorf("Failed to create task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[*oscal.Task]{Data: relationalTask.MarshalOscal()})
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
//	@Param			task	body		oscal.Task	true	"Task object"
//	@Success		200		{object}	handler.GenericDataResponse[oscal.Task]
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

	var task oscal.Task
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
	relationalTask.ParentType = "AssessmentPlan"

	// Update in database
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", taskId, id, "AssessmentPlan").Updates(relationalTask).Error; err != nil {
		h.sugar.Errorf("Failed to update task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscal.Task]{Data: relationalTask.MarshalOscal()})
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

	// Delete task
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", taskId, id, "AssessmentPlan").Delete(&relational.Task{}).Error; err != nil {
		h.sugar.Errorf("Failed to delete task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}
