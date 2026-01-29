package workflows

import (
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type WorkflowExecutionHandler struct {
	sugar   *zap.SugaredLogger
	manager *workflow.Manager
	service *workflows.WorkflowExecutionService
}

func NewWorkflowExecutionHandler(sugar *zap.SugaredLogger, db *gorm.DB, manager *workflow.Manager) *WorkflowExecutionHandler {
	return &WorkflowExecutionHandler{
		sugar:   sugar,
		manager: manager,
		service: workflows.NewWorkflowExecutionService(db),
	}
}

func (h *WorkflowExecutionHandler) Register(api *echo.Group) {
	api.POST("", h.Start)
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.GET("/:id/status", h.GetStatus)
	api.GET("/:id/metrics", h.GetMetrics)
	api.PUT("/:id/cancel", h.Cancel)
	api.POST("/:id/retry", h.Retry)
}

type StartWorkflowExecutionRequest struct {
	WorkflowInstanceID *uuid.UUID `json:"workflow_instance_id" validate:"required"`
	TriggeredBy        string     `json:"triggered_by" validate:"required"`
	TriggeredByID      string     `json:"triggered_by_id"`
}

type CancelWorkflowExecutionRequest struct {
	Reason string `json:"reason"`
}

type WorkflowExecutionResponse struct {
	Data *workflows.WorkflowExecution `json:"data"`
}

type WorkflowExecutionListResponse struct {
	Data []workflows.WorkflowExecution `json:"data"`
}

type WorkflowExecutionStatusResponse struct {
	Data *workflow.ExecutionStatus `json:"data"`
}

type WorkflowExecutionMetricsResponse struct {
	Data *workflow.ExecutionMetrics `json:"data"`
}

// Start godoc
//
//	@Summary		Start workflow execution
//	@Description	Start a new execution of a workflow instance
//	@Tags			Workflow Executions
//	@Accept			json
//	@Produce		json
//	@Param			request	body		StartWorkflowExecutionRequest	true	"Execution details"
//	@Success		201		{object}	WorkflowExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions [post]
func (h *WorkflowExecutionHandler) Start(ctx echo.Context) error {
	var req StartWorkflowExecutionRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Use the manager to start the workflow execution
	executionID, err := h.manager.StartWorkflowExecution(
		ctx.Request().Context(),
		req.WorkflowInstanceID,
		req.TriggeredBy,
		req.TriggeredByID,
	)
	if err != nil {
		h.sugar.Errorw("Failed to start workflow execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the created execution
	execution, err := h.service.GetByID(executionID)
	if err != nil {
		h.sugar.Errorw("Failed to get workflow execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow execution started", "id", executionID)
	return ctx.JSON(http.StatusCreated, WorkflowExecutionResponse{Data: execution})
}

// List godoc
//
//	@Summary		List workflow executions
//	@Description	List all executions for a workflow instance
//	@Tags			Workflow Executions
//	@Produce		json
//	@Param			workflow_instance_id	query		string	true	"Workflow Instance ID"
//	@Param			limit					query		int		false	"Limit"
//	@Param			offset					query		int		false	"Offset"
//	@Success		200						{object}	WorkflowExecutionListResponse
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions [get]
func (h *WorkflowExecutionHandler) List(ctx echo.Context) error {
	workflowInstanceIDStr := ctx.QueryParam("workflow_instance_id")
	if workflowInstanceIDStr == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_instance_id is required")))
	}

	workflowInstanceID, err := uuid.Parse(workflowInstanceIDStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow instance ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Parse pagination parameters (use defaults for now)
	limit := 100
	offset := 0

	// Use the manager to list executions
	executions, err := h.manager.ListExecutions(
		ctx.Request().Context(),
		&workflowInstanceID,
		limit,
		offset,
	)
	if err != nil {
		h.sugar.Errorw("Failed to list workflow executions", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Convert to non-pointer slice
	result := make([]workflows.WorkflowExecution, len(executions))
	for i, exec := range executions {
		result[i] = *exec
	}

	return ctx.JSON(http.StatusOK, WorkflowExecutionListResponse{Data: result})
}

// Get godoc
//
//	@Summary		Get workflow execution
//	@Description	Get workflow execution by ID
//	@Tags			Workflow Executions
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Execution ID"
//	@Success		200	{object}	WorkflowExecutionResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions/{id} [get]
func (h *WorkflowExecutionHandler) Get(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	execution, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowExecutionResponse{Data: execution})
}

// GetStatus godoc
//
//	@Summary		Get workflow execution status
//	@Description	Get detailed status of a workflow execution including step counts
//	@Tags			Workflow Executions
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Execution ID"
//	@Success		200	{object}	WorkflowExecutionStatusResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions/{id}/status [get]
func (h *WorkflowExecutionHandler) GetStatus(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Use the manager to get execution status
	status, err := h.manager.GetExecutionStatus(ctx.Request().Context(), &id)
	if err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow execution status", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowExecutionStatusResponse{Data: status})
}

// GetMetrics godoc
//
//	@Summary		Get workflow execution metrics
//	@Description	Get performance metrics for a workflow execution
//	@Tags			Workflow Executions
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Execution ID"
//	@Success		200	{object}	WorkflowExecutionMetricsResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions/{id}/metrics [get]
func (h *WorkflowExecutionHandler) GetMetrics(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Use the manager to get execution metrics
	metrics, err := h.manager.GetExecutionMetrics(ctx.Request().Context(), &id)
	if err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow execution metrics", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowExecutionMetricsResponse{Data: metrics})
}

// Cancel godoc
//
//	@Summary		Cancel workflow execution
//	@Description	Cancel a running workflow execution
//	@Tags			Workflow Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"Workflow Execution ID"
//	@Param			request	body		CancelWorkflowExecutionRequest	true	"Cancel details"
//	@Success		200		{object}	WorkflowExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions/{id}/cancel [put]
func (h *WorkflowExecutionHandler) Cancel(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req CancelWorkflowExecutionRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reason := req.Reason
	if reason == "" {
		reason = "Cancelled by user"
	}

	// Use the manager to cancel the execution
	if err := h.manager.CancelExecution(ctx.Request().Context(), &id, reason); err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to cancel workflow execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the updated execution
	execution, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get workflow execution after cancellation", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow execution cancelled", "id", id)
	return ctx.JSON(http.StatusOK, WorkflowExecutionResponse{Data: execution})
}

// Retry godoc
//
//	@Summary		Retry workflow execution
//	@Description	Create a new execution to retry a failed workflow
//	@Tags			Workflow Executions
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Execution ID"
//	@Success		201	{object}	WorkflowExecutionResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions/{id}/retry [post]
func (h *WorkflowExecutionHandler) Retry(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Use the manager to retry the execution
	newExecutionID, err := h.manager.RetryExecution(ctx.Request().Context(), &id)
	if err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to retry workflow execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the new execution
	execution, err := h.service.GetByID(newExecutionID)
	if err != nil {
		h.sugar.Errorw("Failed to get new workflow execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow execution retried", "original_id", id, "new_id", newExecutionID)
	return ctx.JSON(http.StatusCreated, WorkflowExecutionResponse{Data: execution})
}
