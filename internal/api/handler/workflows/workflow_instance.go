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

type WorkflowInstanceHandler struct {
	sugar   *zap.SugaredLogger
	service *workflows.WorkflowInstanceService
}

func NewWorkflowInstanceHandler(sugar *zap.SugaredLogger, db *gorm.DB) *WorkflowInstanceHandler {
	return &WorkflowInstanceHandler{
		sugar:   sugar,
		service: workflows.NewWorkflowInstanceService(db),
	}
}

func (h *WorkflowInstanceHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
	api.PUT("/:id/activate", h.Activate)
	api.PUT("/:id/deactivate", h.Deactivate)
}

type CreateWorkflowInstanceRequest struct {
	WorkflowDefinitionID *uuid.UUID `json:"workflow-definition-id" validate:"required"`
	Name                 string     `json:"name" validate:"required"`
	Description          string     `json:"description"`
	SystemSecurityPlanID string     `json:"system-id" validate:"required"`
	Cadence              string     `json:"cadence"`
	IsActive             *bool      `json:"is-active"`
}

type UpdateWorkflowInstanceRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Cadence     *string `json:"cadence"`
	IsActive    *bool   `json:"is-active"`
}

type WorkflowInstanceResponse struct {
	Data *workflows.WorkflowInstance `json:"data"`
}

type WorkflowInstanceListResponse struct {
	Data []workflows.WorkflowInstance `json:"data"`
}

// Create godoc
//
//	@Summary		Create workflow instance
//	@Description	Create a new workflow instance for a specific system
//	@Tags			Workflow Instances
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateWorkflowInstanceRequest	true	"Workflow instance details"
//	@Success		201		{object}	WorkflowInstanceResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/instances [post]
func (h *WorkflowInstanceHandler) Create(ctx echo.Context) error {
	var req CreateWorkflowInstanceRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	systemId, err := uuid.Parse(req.SystemSecurityPlanID)
	if err != nil {
		h.sugar.Errorw("Failed to parse system security plan ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: req.WorkflowDefinitionID,
		Name:                 req.Name,
		Description:          req.Description,
		SystemSecurityPlanID: &systemId,
		Cadence:              req.Cadence,
		IsActive:             true, // Default to active
	}

	if req.IsActive != nil {
		instance.IsActive = *req.IsActive
	}

	if err := h.service.Create(instance); err != nil {
		h.sugar.Errorw("Failed to create workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow instance created", "id", instance.ID)
	return ctx.JSON(http.StatusCreated, WorkflowInstanceResponse{Data: instance})
}

// List godoc
//
//	@Summary		List workflow instances
//	@Description	List all workflow instances with optional filtering
//	@Tags			Workflow Instances
//	@Produce		json
//	@Param			workflow_definition_id	query		string	false	"Filter by Workflow Definition ID"
//	@Param			system_security_plan_id	query		string	false	"Filter by System Security Plan ID"
//	@Param			is_active				query		bool	false	"Filter by Active Status"
//	@Success		200						{object}	WorkflowInstanceListResponse
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/instances [get]
func (h *WorkflowInstanceHandler) List(ctx echo.Context) error {
	workflowDefIDStr := ctx.QueryParam("workflow_definition_id")
	systemSecurityPlanIDStr := ctx.QueryParam("system_security_plan_id")
	isActiveStr := ctx.QueryParam("is_active")

	var instances []workflows.WorkflowInstance
	var err error

	// Build filters map
	filters := make(map[string]interface{})
	if workflowDefIDStr != "" {
		workflowDefID, parseErr := uuid.Parse(workflowDefIDStr)
		if parseErr != nil {
			h.sugar.Errorw("Invalid workflow definition ID", "error", parseErr)
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}
		filters["workflow_definition_id"] = workflowDefID
	}
	if systemSecurityPlanIDStr != "" {
		systemSecurityPlanID, parseErr := uuid.Parse(systemSecurityPlanIDStr)
		if parseErr != nil {
			h.sugar.Errorw("Invalid system security plan ID", "error", parseErr)
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}
		filters["system_security_plan_id"] = systemSecurityPlanID
	}

	instances, _, err = h.service.GetAll(1000, 0, filters)

	if err != nil {
		h.sugar.Errorw("Failed to list workflow instances", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Filter by active status if provided
	if isActiveStr != "" {
		isActive := isActiveStr == "true"
		filtered := make([]workflows.WorkflowInstance, 0)
		for _, instance := range instances {
			if instance.IsActive == isActive {
				filtered = append(filtered, instance)
			}
		}
		instances = filtered
	}

	return ctx.JSON(http.StatusOK, WorkflowInstanceListResponse{Data: instances})
}

// Get godoc
//
//	@Summary		Get workflow instance
//	@Description	Get workflow instance by ID
//	@Tags			Workflow Instances
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Instance ID"
//	@Success		200	{object}	WorkflowInstanceResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/instances/{id} [get]
func (h *WorkflowInstanceHandler) Get(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow instance ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	instance, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowInstanceResponse{Data: instance})
}

// Update godoc
//
//	@Summary		Update workflow instance
//	@Description	Update workflow instance by ID
//	@Tags			Workflow Instances
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"Workflow Instance ID"
//	@Param			request	body		UpdateWorkflowInstanceRequest	true	"Updated workflow instance details"
//	@Success		200		{object}	WorkflowInstanceResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/instances/{id} [put]
func (h *WorkflowInstanceHandler) Update(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow instance ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req UpdateWorkflowInstanceRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	instance, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if req.Name != nil {
		instance.Name = *req.Name
	}
	if req.Description != nil {
		instance.Description = *req.Description
	}
	if req.Cadence != nil {
		instance.Cadence = *req.Cadence
	}
	if req.IsActive != nil {
		instance.IsActive = *req.IsActive
	}

	if err := h.service.Update(&id, instance); err != nil {
		h.sugar.Errorw("Failed to update workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow instance updated", "id", instance.ID)
	return ctx.JSON(http.StatusOK, WorkflowInstanceResponse{Data: instance})
}

// Delete godoc
//
//	@Summary		Delete workflow instance
//	@Description	Delete workflow instance by ID
//	@Tags			Workflow Instances
//	@Produce		json
//	@Param			id	path	string	true	"Workflow Instance ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/instances/{id} [delete]
func (h *WorkflowInstanceHandler) Delete(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow instance ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.Delete(&id); err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to delete workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow instance deleted", "id", id)
	return ctx.NoContent(http.StatusNoContent)
}

// Activate godoc
//
//	@Summary		Activate workflow instance
//	@Description	Activate a workflow instance to enable scheduled executions
//	@Tags			Workflow Instances
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Instance ID"
//	@Success		200	{object}	WorkflowInstanceResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/instances/{id}/activate [put]
func (h *WorkflowInstanceHandler) Activate(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow instance ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if instance exists first
	_, err = h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.service.Activate(&id); err != nil {
		h.sugar.Errorw("Failed to activate workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	instance, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get workflow instance after activation", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow instance activated", "id", id)
	return ctx.JSON(http.StatusOK, WorkflowInstanceResponse{Data: instance})
}

// Deactivate godoc
//
//	@Summary		Deactivate workflow instance
//	@Description	Deactivate a workflow instance to disable scheduled executions
//	@Tags			Workflow Instances
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Instance ID"
//	@Success		200	{object}	WorkflowInstanceResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/instances/{id}/deactivate [put]
func (h *WorkflowInstanceHandler) Deactivate(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow instance ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if instance exists first
	_, err = h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.service.Deactivate(&id); err != nil {
		h.sugar.Errorw("Failed to deactivate workflow instance", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	instance, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get workflow instance after deactivation", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow instance deactivated", "id", id)
	return ctx.JSON(http.StatusOK, WorkflowInstanceResponse{Data: instance})
}
