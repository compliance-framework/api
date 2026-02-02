package workflows

import (
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "not assigned to role") ||
		strings.Contains(errMsg, "no assignment found")
}

type StepExecutionHandler struct {
	sugar             *zap.SugaredLogger
	db                *gorm.DB
	service           *workflows.StepExecutionService
	transitionService *workflow.StepTransitionService
}

func NewStepExecutionHandler(sugar *zap.SugaredLogger, db *gorm.DB, transitionService *workflow.StepTransitionService) *StepExecutionHandler {
	return &StepExecutionHandler{
		sugar:             sugar,
		db:                db,
		service:           transitionService.GetStepExecutionService(), // Use the same service as transition service
		transitionService: transitionService,
	}
}

func (h *StepExecutionHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.PUT("/:id/transition", h.TransitionStep)
	api.GET("/:id/evidence-requirements", h.GetEvidenceRequirements)
	api.GET("/:id/can-transition", h.CanTransition)
	api.PUT("/:id/fail", h.Fail)
}

type TransitionStepRequest struct {
	Status   string                        `json:"status" validate:"required,oneof=in_progress completed"`
	Evidence []workflow.EvidenceSubmission `json:"evidence,omitempty"`
	Notes    string                        `json:"notes,omitempty"`
	UserID   string                        `json:"user-id" validate:"required"`
	UserType string                        `json:"user-type" validate:"required,oneof=user group email"`
}

type FailStepRequest struct {
	Reason string `json:"reason" validate:"required"`
}

type StepExecutionResponse struct {
	Data *workflows.StepExecution `json:"data"`
}

type StepExecutionListResponse struct {
	Data []workflows.StepExecution `json:"data"`
}

// List godoc
//
//	@Summary		List step executions
//	@Description	List all step executions for a workflow execution
//	@Tags			Step Executions
//	@Produce		json
//	@Param			workflow_execution_id	query		string	true	"Workflow Execution ID"
//	@Success		200						{object}	StepExecutionListResponse
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions [get]
func (h *StepExecutionHandler) List(ctx echo.Context) error {
	workflowExecIDStr := ctx.QueryParam("workflow_execution_id")
	if workflowExecIDStr == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_execution_id is required")))
	}

	workflowExecID, err := uuid.Parse(workflowExecIDStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stepExecutions, err := h.service.GetByWorkflowExecutionID(&workflowExecID)
	if err != nil {
		h.sugar.Errorw("Failed to list step executions", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, StepExecutionListResponse{Data: stepExecutions})
}

// Get godoc
//
//	@Summary		Get step execution
//	@Description	Get step execution by ID
//	@Tags			Step Executions
//	@Produce		json
//	@Param			id	path		string	true	"Step Execution ID"
//	@Success		200	{object}	StepExecutionResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id} [get]
func (h *StepExecutionHandler) Get(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stepExecution, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get step execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, StepExecutionResponse{Data: stepExecution})
}

// TransitionStep godoc
//
//	@Summary		Transition step execution status
//	@Description	Transition a step execution status with role verification and evidence validation
//	@Tags			Step Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Step Execution ID"
//	@Param			request	body		TransitionStepRequest	true	"Transition request"
//	@Success		200		{object}	StepExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		403		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/transition [put]
func (h *StepExecutionHandler) TransitionStep(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req TransitionStepRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to workflow.StepTransitionRequest
	transitionReq := &workflow.StepTransitionRequest{
		Status:   req.Status,
		Evidence: req.Evidence,
		Notes:    req.Notes,
		UserID:   req.UserID,
		UserType: req.UserType,
	}

	// Perform the transition with role verification and evidence validation
	if err := h.transitionService.TransitionStepStatus(ctx.Request().Context(), &id, transitionReq); err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		// Check if it's a permission error
		if isPermissionError(err) {
			return ctx.JSON(http.StatusForbidden, api.NewError(err))
		}
		h.sugar.Errorw("Failed to transition step execution", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	stepExecution, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get step execution after transition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Step execution transitioned", "id", id, "status", req.Status, "user", req.UserID)
	return ctx.JSON(http.StatusOK, StepExecutionResponse{Data: stepExecution})
}

// GetEvidenceRequirements godoc
//
//	@Summary		Get evidence requirements for step
//	@Description	Get the evidence requirements for a step execution
//	@Tags			Step Executions
//	@Produce		json
//	@Param			id	path		string	true	"Step Execution ID"
//	@Success		200	{object}	map[string]interface{}
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/evidence-requirements [get]
func (h *StepExecutionHandler) GetEvidenceRequirements(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	requirements, err := h.transitionService.GetEvidenceRequirements(&id)
	if err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get evidence requirements", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"data": requirements,
	})
}

// CanTransition godoc
//
//	@Summary		Check if user can transition step
//	@Description	Check if a user has permission to transition a step execution
//	@Tags			Step Executions
//	@Produce		json
//	@Param			id			path		string	true	"Step Execution ID"
//	@Param			user_id		query		string	true	"User ID"
//	@Param			user_type	query		string	true	"User Type (user, group, email)"
//	@Success		200			{object}	map[string]interface{}
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/can-transition [get]
func (h *StepExecutionHandler) CanTransition(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	userID := ctx.QueryParam("user_id")
	userType := ctx.QueryParam("user_type")

	if userID == "" || userType == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "user_id and user_type are required")))
	}

	canTransition, err := h.transitionService.CanUserTransitionStep(&id, userID, userType)
	if err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to check transition permission", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"can-transition": canTransition,
			"user-id":        userID,
			"user-type":      userType,
		},
	})
}

// Fail godoc
//
//	@Summary		Fail step execution
//	@Description	Mark a step execution as failed with a reason
//	@Tags			Step Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"Step Execution ID"
//	@Param			request	body		FailStepRequest	true	"Failure details"
//	@Success		200		{object}	StepExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/fail [put]
func (h *StepExecutionHandler) Fail(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req FailStepRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.Fail(&id, req.Reason); err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to mark step execution as failed", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	stepExecution, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get step execution after failure", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Step execution marked as failed", "id", id, "reason", req.Reason)
	return ctx.JSON(http.StatusOK, StepExecutionResponse{Data: stepExecution})
}
