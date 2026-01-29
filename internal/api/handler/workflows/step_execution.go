package workflows

import (
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type StepExecutionHandler struct {
	sugar   *zap.SugaredLogger
	db      *gorm.DB
	service *workflows.StepExecutionService
}

func NewStepExecutionHandler(sugar *zap.SugaredLogger, db *gorm.DB) *StepExecutionHandler {
	return &StepExecutionHandler{
		sugar:   sugar,
		db:      db,
		service: workflows.NewStepExecutionService(db),
	}
}

func (h *StepExecutionHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.PUT("/:id/status", h.UpdateStatus)
	api.POST("/:id/evidence", h.SubmitEvidence)
	api.PUT("/:id/fail", h.Fail)
}

type UpdateStepStatusRequest struct {
	Status string `json:"status" validate:"required"`
}

type SubmitEvidenceRequest struct {
	EvidenceID *uuid.UUID `json:"evidence_id" validate:"required"`
	Notes      string     `json:"notes"`
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

// UpdateStatus godoc
//
//	@Summary		Update step execution status
//	@Description	Update the status of a step execution
//	@Tags			Step Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Step Execution ID"
//	@Param			request	body		UpdateStepStatusRequest	true	"Status update"
//	@Success		200		{object}	StepExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/status [put]
func (h *StepExecutionHandler) UpdateStatus(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req UpdateStepStatusRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.UpdateStatus(&id, req.Status); err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to update step execution status", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	stepExecution, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get step execution after update", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Step execution status updated", "id", id, "status", req.Status)
	return ctx.JSON(http.StatusOK, StepExecutionResponse{Data: stepExecution})
}

// SubmitEvidence godoc
//
//	@Summary		Submit evidence for step execution
//	@Description	Submit evidence for a step execution
//	@Tags			Step Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Step Execution ID"
//	@Param			request	body		SubmitEvidenceRequest	true	"Evidence submission"
//	@Success		200		{object}	StepExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/evidence [post]
func (h *StepExecutionHandler) SubmitEvidence(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step execution ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req SubmitEvidenceRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Create evidence record directly in DB
	evidence := &workflows.StepEvidence{
		StepExecutionID: &id,
		EvidenceID:      req.EvidenceID,
		Description:     req.Notes,
	}

	if err := h.db.Create(evidence).Error; err != nil {
		h.sugar.Errorw("Failed to submit evidence", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	stepExecution, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get step execution after evidence submission", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Evidence submitted for step execution", "id", id, "evidence_id", req.EvidenceID)
	return ctx.JSON(http.StatusOK, StepExecutionResponse{Data: stepExecution})
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
