package workflows

import (
	"errors"
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
	*BaseHandler
	db                *gorm.DB
	manager           *workflow.Manager
	service           *workflows.WorkflowExecutionService
	assignmentService *workflow.AssignmentService
}

func NewWorkflowExecutionHandler(
	sugar *zap.SugaredLogger,
	db *gorm.DB,
	manager *workflow.Manager,
	assignmentService *workflow.AssignmentService,
) *WorkflowExecutionHandler {
	return &WorkflowExecutionHandler{
		BaseHandler:       NewBaseHandler(sugar),
		db:                db,
		manager:           manager,
		service:           workflows.NewWorkflowExecutionService(db),
		assignmentService: assignmentService,
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
	api.PUT("/:id/reassign-role", h.ReassignRole)
}

type StartWorkflowExecutionRequest struct {
	WorkflowInstanceID *uuid.UUID `json:"workflow-instance-id" validate:"required"`
	TriggeredBy        string     `json:"triggered-by" validate:"required"`
	TriggeredByID      string     `json:"triggered-by-id"`
}

type CancelWorkflowExecutionRequest struct {
	Reason string `json:"reason"`
}

type ReassignRoleRequest struct {
	RoleName          string `json:"role-name" validate:"required"`
	NewAssignedToType string `json:"new-assigned-to-type" validate:"required,oneof=user group email"`
	NewAssignedToID   string `json:"new-assigned-to-id" validate:"required"`
	Reason            string `json:"reason,omitempty"`
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

type BulkReassignRoleResponse struct {
	Data BulkReassignRoleResponseData `json:"data"`
}

type BulkReassignRoleResponseData struct {
	ExecutionID                uuid.UUID   `json:"execution-id"`
	RoleName                   string      `json:"role-name"`
	ReassignedCount            int         `json:"reassigned-count"`
	ReassignedStepExecutionIDs []uuid.UUID `json:"reassigned-step-execution-ids"`
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
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	// Use the manager to start the workflow execution
	// TODO: Consider adding timeout to context for long-running workflow operations
	// Currently using request context directly - may want to add WithTimeout wrapper
	opts := workflow.StartWorkflowOptions{
		TriggeredBy:   req.TriggeredBy,
		TriggeredByID: req.TriggeredByID,
	}

	executionID, err := h.manager.StartWorkflowExecution(
		ctx.Request().Context(),
		req.WorkflowInstanceID,
		opts,
	)
	if err != nil {
		return h.HandleServiceError(ctx, err, "start", "workflow execution")
	}

	// Get the created execution
	execution, err := h.service.GetByID(executionID)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow execution")
	}

	h.sugar.Infow("Workflow execution started", "id", executionID)
	return h.RespondCreated(ctx, WorkflowExecutionResponse{Data: execution})
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
		return h.HandleServiceError(ctx, err, "parse", "workflow instance ID")
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
		return h.HandleServiceError(ctx, err, "list", "workflow executions")
	}

	// Convert to non-pointer slice
	result := make([]workflows.WorkflowExecution, len(executions))
	for i, exec := range executions {
		result[i] = *exec
	}

	return h.RespondOK(ctx, WorkflowExecutionListResponse{Data: result})
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
	id, err := h.ParseUUID(ctx, "id", "workflow execution")
	if err != nil {
		return HandleError(err)
	}

	execution, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow execution")
	}

	return h.RespondOK(ctx, WorkflowExecutionResponse{Data: execution})
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
	id, err := h.ParseUUID(ctx, "id", "workflow execution")
	if err != nil {
		return HandleError(err)
	}

	// Use the manager to get execution status
	status, err := h.manager.GetExecutionStatus(ctx.Request().Context(), id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow execution status")
	}

	return h.RespondOK(ctx, WorkflowExecutionStatusResponse{Data: status})
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
	id, err := h.ParseUUID(ctx, "id", "workflow execution")
	if err != nil {
		return HandleError(err)
	}

	// Use the manager to get execution metrics
	metrics, err := h.manager.GetExecutionMetrics(ctx.Request().Context(), id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow execution metrics")
	}

	return h.RespondOK(ctx, WorkflowExecutionMetricsResponse{Data: metrics})
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
	id, err := h.ParseUUID(ctx, "id", "workflow execution")
	if err != nil {
		return HandleError(err)
	}

	var req CancelWorkflowExecutionRequest
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	reason := req.Reason
	if reason == "" {
		reason = "Cancelled by user"
	}

	// Use the manager to cancel the execution
	if err := h.manager.CancelExecution(ctx.Request().Context(), id, reason); err != nil {
		return h.HandleServiceError(ctx, err, "cancel", "workflow execution")
	}

	// Get the updated execution
	execution, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow execution after cancellation")
	}

	h.sugar.Infow("Workflow execution cancelled", "id", id)
	return h.RespondOK(ctx, WorkflowExecutionResponse{Data: execution})
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
	id, err := h.ParseUUID(ctx, "id", "workflow execution")
	if err != nil {
		return HandleError(err)
	}

	// Use the manager to retry the execution
	newExecutionID, err := h.manager.RetryExecution(ctx.Request().Context(), id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "retry", "workflow execution")
	}

	// Get the new execution
	execution, err := h.service.GetByID(newExecutionID)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "new workflow execution")
	}

	h.sugar.Infow("Workflow execution retried", "original_id", id, "new_id", newExecutionID)
	return h.RespondCreated(ctx, WorkflowExecutionResponse{Data: execution})
}

// ReassignRole godoc
//
//	@Summary		Bulk reassign steps by role
//	@Description	Reassign eligible steps in an execution for a given role
//	@Tags			Workflow Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Workflow Execution ID"
//	@Param			request	body		ReassignRoleRequest	true	"Bulk reassignment details"
//	@Success		200		{object}	BulkReassignRoleResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/executions/{id}/reassign-role [put]
func (h *WorkflowExecutionHandler) ReassignRole(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "workflow execution")
	if err != nil {
		return HandleError(err)
	}

	var req ReassignRoleRequest
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	reassignedByUserID, reassignedByEmail, err := h.GetActorFromClaims(ctx, h.db)
	if err != nil {
		return HandleError(err)
	}

	result, err := h.assignmentService.BulkReassignByRole(
		ctx.Request().Context(),
		*id,
		req.RoleName,
		workflow.Assignee{
			Type: req.NewAssignedToType,
			ID:   req.NewAssignedToID,
		},
		req.Reason,
		reassignedByUserID,
		reassignedByEmail,
	)
	if err != nil {
		if errors.Is(err, workflow.ErrInvalidAssignee) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		if errors.Is(err, gorm.ErrRecordNotFound) || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.HandleServiceError(ctx, err, "bulk reassign", "workflow execution")
	}

	return h.RespondOK(ctx, BulkReassignRoleResponse{
		Data: BulkReassignRoleResponseData{
			ExecutionID:                result.ExecutionID,
			RoleName:                   result.RoleName,
			ReassignedCount:            result.ReassignedCount,
			ReassignedStepExecutionIDs: result.ReassignedStepExecIDs,
		},
	})
}
