package workflows

import (
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type WorkflowStepDefinitionHandler struct {
	sugar   *zap.SugaredLogger
	service *workflows.WorkflowStepDefinitionService
}

func NewWorkflowStepDefinitionHandler(sugar *zap.SugaredLogger, db *gorm.DB) *WorkflowStepDefinitionHandler {
	return &WorkflowStepDefinitionHandler{
		sugar:   sugar,
		service: workflows.NewWorkflowStepDefinitionService(db),
	}
}

func (h *WorkflowStepDefinitionHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("", h.ListByWorkflowDefinition)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
	api.GET("/:id/dependencies", h.GetDependencies)
}

type CreateWorkflowStepDefinitionRequest struct {
	WorkflowDefinitionID *uuid.UUID `json:"workflow_definition_id" validate:"required"`
	Name                 string     `json:"name" validate:"required"`
	Description          string     `json:"description"`
	ResponsibleRole      string     `json:"responsible_role" validate:"required"`
	EvidenceRequired     string     `json:"evidence_required"`
	EstimatedDuration    int        `json:"estimated_duration"`
	DependsOn            []string   `json:"depends_on"` // Array of step IDs this step depends on
}

type UpdateWorkflowStepDefinitionRequest struct {
	Name              *string `json:"name"`
	Description       *string `json:"description"`
	ResponsibleRole   *string `json:"responsible_role"`
	EvidenceRequired  *string `json:"evidence_required"`
	EstimatedDuration *int    `json:"estimated_duration"`
}

type WorkflowStepDefinitionResponse struct {
	Data *workflows.WorkflowStepDefinition `json:"data"`
}

type WorkflowStepDefinitionListResponse struct {
	Data []workflows.WorkflowStepDefinition `json:"data"`
}

// Create godoc
//
//	@Summary		Create workflow step definition
//	@Description	Create a new step definition for a workflow
//	@Tags			Workflow Step Definitions
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateWorkflowStepDefinitionRequest	true	"Step definition details"
//	@Success		201		{object}	WorkflowStepDefinitionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/steps [post]
func (h *WorkflowStepDefinitionHandler) Create(ctx echo.Context) error {
	var req CreateWorkflowStepDefinitionRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: req.WorkflowDefinitionID,
		Name:                 req.Name,
		Description:          req.Description,
		ResponsibleRole:      req.ResponsibleRole,
		EvidenceRequired:     req.EvidenceRequired,
		EstimatedDuration:    req.EstimatedDuration,
	}

	if err := h.service.Create(stepDef); err != nil {
		h.sugar.Errorw("Failed to create workflow step definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Add dependencies if provided
	if len(req.DependsOn) > 0 {
		for _, depIDStr := range req.DependsOn {
			depID, err := uuid.Parse(depIDStr)
			if err != nil {
				h.sugar.Warnw("Invalid dependency ID", "dependency_id", depIDStr, "error", err)
				continue
			}
			if err := h.service.AddDependency(stepDef.ID, &depID); err != nil {
				h.sugar.Warnw("Failed to add dependency", "step_id", stepDef.ID, "dependency_id", depID, "error", err)
			}
		}
	}

	h.sugar.Infow("Workflow step definition created", "id", stepDef.ID)
	return ctx.JSON(http.StatusCreated, WorkflowStepDefinitionResponse{Data: stepDef})
}

// ListByWorkflowDefinition godoc
//
//	@Summary		List workflow step definitions
//	@Description	List all step definitions for a workflow definition
//	@Tags			Workflow Step Definitions
//	@Produce		json
//	@Param			workflow_definition_id	query		string	true	"Workflow Definition ID"
//	@Success		200						{object}	WorkflowStepDefinitionListResponse
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/steps [get]
func (h *WorkflowStepDefinitionHandler) ListByWorkflowDefinition(ctx echo.Context) error {
	workflowDefIDStr := ctx.QueryParam("workflow_definition_id")
	if workflowDefIDStr == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_definition_id is required")))
	}

	workflowDefID, err := uuid.Parse(workflowDefIDStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	steps, err := h.service.GetByWorkflowDefinitionID(&workflowDefID)
	if err != nil {
		h.sugar.Errorw("Failed to list workflow step definitions", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowStepDefinitionListResponse{Data: steps})
}

// Get godoc
//
//	@Summary		Get workflow step definition
//	@Description	Get workflow step definition by ID
//	@Tags			Workflow Step Definitions
//	@Produce		json
//	@Param			id	path		string	true	"Step Definition ID"
//	@Success		200	{object}	WorkflowStepDefinitionResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/steps/{id} [get]
func (h *WorkflowStepDefinitionHandler) Get(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stepDef, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow step definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowStepDefinitionResponse{Data: stepDef})
}

// Update godoc
//
//	@Summary		Update workflow step definition
//	@Description	Update workflow step definition by ID
//	@Tags			Workflow Step Definitions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"Step Definition ID"
//	@Param			request	body		UpdateWorkflowStepDefinitionRequest	true	"Updated step definition details"
//	@Success		200		{object}	WorkflowStepDefinitionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/steps/{id} [put]
func (h *WorkflowStepDefinitionHandler) Update(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req UpdateWorkflowStepDefinitionRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stepDef, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow step definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if req.Name != nil {
		stepDef.Name = *req.Name
	}
	if req.Description != nil {
		stepDef.Description = *req.Description
	}
	if req.ResponsibleRole != nil {
		stepDef.ResponsibleRole = *req.ResponsibleRole
	}
	if req.EvidenceRequired != nil {
		stepDef.EvidenceRequired = *req.EvidenceRequired
	}
	if req.EstimatedDuration != nil {
		stepDef.EstimatedDuration = *req.EstimatedDuration
	}

	if err := h.service.Update(&id, stepDef); err != nil {
		h.sugar.Errorw("Failed to update workflow step definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow step definition updated", "id", stepDef.ID)
	return ctx.JSON(http.StatusOK, WorkflowStepDefinitionResponse{Data: stepDef})
}

// Delete godoc
//
//	@Summary		Delete workflow step definition
//	@Description	Delete workflow step definition by ID
//	@Tags			Workflow Step Definitions
//	@Produce		json
//	@Param			id	path	string	true	"Step Definition ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/steps/{id} [delete]
func (h *WorkflowStepDefinitionHandler) Delete(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.Delete(&id); err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to delete workflow step definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow step definition deleted", "id", id)
	return ctx.NoContent(http.StatusNoContent)
}

// GetDependencies godoc
//
//	@Summary		Get step dependencies
//	@Description	Get all dependencies for a workflow step definition
//	@Tags			Workflow Step Definitions
//	@Produce		json
//	@Param			id	path		string	true	"Step Definition ID"
//	@Success		200	{object}	WorkflowStepDefinitionListResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/steps/{id}/dependencies [get]
func (h *WorkflowStepDefinitionHandler) GetDependencies(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid step definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	dependencies, err := h.service.GetDependencies(&id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get step dependencies", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowStepDefinitionListResponse{Data: dependencies})
}
