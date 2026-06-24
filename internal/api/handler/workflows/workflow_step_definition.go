package workflows

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type WorkflowStepDefinitionHandler struct {
	*BaseHandler
	service *workflows.WorkflowStepDefinitionService
}

func (h *WorkflowStepDefinitionHandler) updateStepDependencies(stepID *uuid.UUID, desired []string) (int, error) {
	if stepID == nil {
		return http.StatusInternalServerError, fmt.Errorf("step id cannot be nil")
	}

	if desired == nil {
		desired = []string{}
	}

	desiredMap := make(map[string]*uuid.UUID)
	for _, depIDStr := range desired {
		depUUID, err := uuid.Parse(depIDStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid dependency id: %s", depIDStr)
		}
		if depUUID.String() == stepID.String() {
			return http.StatusBadRequest, fmt.Errorf("step cannot depend on itself")
		}
		depCopy := depUUID
		desiredMap[depUUID.String()] = &depCopy
	}

	currentDeps, err := h.service.GetDependencies(stepID)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	currentMap := make(map[string]*uuid.UUID)
	for _, dep := range currentDeps {
		if dep.ID == nil {
			continue
		}
		depIDStr := dep.ID.String()
		depCopy := *dep.ID
		currentMap[depIDStr] = &depCopy
		if _, ok := desiredMap[depIDStr]; !ok {
			if err := h.service.RemoveDependency(stepID, dep.ID); err != nil {
				return dependencyServiceErrorStatus(err), err
			}
		}
	}

	for depIDStr, depUUID := range desiredMap {
		if _, exists := currentMap[depIDStr]; exists {
			continue
		}
		if err := h.service.AddDependency(stepID, depUUID); err != nil {
			return dependencyServiceErrorStatus(err), err
		}
	}

	return http.StatusOK, nil
}

func dependencyServiceErrorStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "not found") || strings.Contains(msg, "already exists") || strings.Contains(msg, "circular") || strings.Contains(msg, "does not exist") {
		return http.StatusBadRequest
	}

	return http.StatusInternalServerError
}

func NewWorkflowStepDefinitionHandler(sugar *zap.SugaredLogger, db *gorm.DB) *WorkflowStepDefinitionHandler {
	return &WorkflowStepDefinitionHandler{
		BaseHandler: NewBaseHandler(sugar),
		service:     workflows.NewWorkflowStepDefinitionService(db),
	}
}

func (h *WorkflowStepDefinitionHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.POST("", h.Create, guard.Create())
	api.GET("", h.ListByWorkflowDefinition, guard.Read())
	api.GET("/:id", h.Get, guard.Read())
	api.PUT("/:id", h.Update, guard.Update())
	api.DELETE("/:id", h.Delete, guard.Delete())
	api.GET("/:id/dependencies", h.GetDependencies, guard.Read())
}

type CreateWorkflowStepDefinitionRequest struct {
	WorkflowDefinitionID *uuid.UUID                      `json:"workflow-definition-id" validate:"required"`
	Name                 string                          `json:"name" validate:"required"`
	Description          string                          `json:"description"`
	ResponsibleRole      string                          `json:"responsible-role" validate:"required"`
	EvidenceRequired     []workflows.EvidenceRequirement `json:"evidence-required"`
	EstimatedDuration    int                             `json:"estimated-duration"`
	GracePeriodDays      *int                            `json:"grace-period-days"`
	DependsOn            []string                        `json:"depends-on"` // Array of step IDs this step depends on
}

type UpdateWorkflowStepDefinitionRequest struct {
	Name              *string                          `json:"name"`
	Description       *string                          `json:"description"`
	ResponsibleRole   *string                          `json:"responsible-role"`
	EvidenceRequired  *[]workflows.EvidenceRequirement `json:"evidence-required"`
	EstimatedDuration *int                             `json:"estimated-duration"`
	GracePeriodDays   *int                             `json:"grace-period-days"`
	DependsOn         *[]string                        `json:"depends-on"`
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
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: req.WorkflowDefinitionID,
		Name:                 req.Name,
		Description:          req.Description,
		ResponsibleRole:      req.ResponsibleRole,
		EvidenceRequired:     req.EvidenceRequired,
		EstimatedDuration:    req.EstimatedDuration,
		GracePeriodDays:      req.GracePeriodDays,
	}

	if err := h.service.Create(stepDef); err != nil {
		return h.HandleServiceError(ctx, err, "create", "workflow step definition")
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
	output, err := h.service.GetByID(stepDef.ID)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow step definition")
	}
	h.sugar.Infow("Workflow step definition created", "id", output.ID)
	return h.RespondCreated(ctx, WorkflowStepDefinitionResponse{Data: output})
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
		h.sugar.Errorw("Invalid workflow definition ID", "error", err, "value", workflowDefIDStr)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	steps, err := h.service.GetByWorkflowDefinitionID(&workflowDefID)
	if err != nil {
		return h.HandleServiceError(ctx, err, "list", "workflow step definitions")
	}

	return h.RespondOK(ctx, WorkflowStepDefinitionListResponse{Data: steps})
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
	id, err := h.ParseUUID(ctx, "id", "step definition")
	if err != nil {
		return HandleError(err)
	}

	stepDef, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow step definition")
	}

	return h.RespondOK(ctx, WorkflowStepDefinitionResponse{Data: stepDef})
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
	id, err := h.ParseUUID(ctx, "id", "step definition")
	if err != nil {
		return HandleError(err)
	}

	var req UpdateWorkflowStepDefinitionRequest
	if err := h.Bind(ctx, &req); err != nil {
		return HandleError(err)
	}

	stepDef, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow step definition")
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
	if req.GracePeriodDays != nil {
		stepDef.GracePeriodDays = req.GracePeriodDays
	}

	if err := h.service.Update(id, stepDef); err != nil {
		return h.HandleServiceError(ctx, err, "update", "workflow step definition")
	}

	if req.DependsOn != nil {
		status, err := h.updateStepDependencies(stepDef.ID, *req.DependsOn)
		if err != nil {
			h.sugar.Errorw("Failed to update workflow step dependencies", "error", err, "step_id", stepDef.ID)
			return ctx.JSON(status, api.NewError(err))
		}
	}

	// Reload step definition to return fresh relationships
	updatedStepDef, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "reload", "workflow step definition")
	}

	h.sugar.Infow("Workflow step definition updated", "id", updatedStepDef.ID)
	return h.RespondOK(ctx, WorkflowStepDefinitionResponse{Data: updatedStepDef})
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
	id, err := h.ParseUUID(ctx, "id", "step definition")
	if err != nil {
		return HandleError(err)
	}

	if err := h.service.Delete(id); err != nil {
		return h.HandleServiceError(ctx, err, "delete", "workflow step definition")
	}

	h.sugar.Infow("Workflow step definition deleted", "id", id)
	return h.RespondNoContent(ctx)
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
	id, err := h.ParseUUID(ctx, "id", "step definition")
	if err != nil {
		return HandleError(err)
	}

	dependencies, err := h.service.GetDependencies(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "step dependencies")
	}

	return h.RespondOK(ctx, WorkflowStepDefinitionListResponse{Data: dependencies})
}
