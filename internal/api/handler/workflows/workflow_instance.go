package workflows

import (
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type WorkflowInstanceHandler struct {
	*BaseHandler
	db      *gorm.DB
	service *workflows.WorkflowInstanceService
}

func NewWorkflowInstanceHandler(sugar *zap.SugaredLogger, db *gorm.DB) *WorkflowInstanceHandler {
	return &WorkflowInstanceHandler{
		BaseHandler: NewBaseHandler(sugar),
		db:          db,
		service:     workflows.NewWorkflowInstanceService(db),
	}
}

func (h *WorkflowInstanceHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.POST("", h.Create, guard.Create())
	api.GET("", h.List, guard.Read())
	api.GET("/:id", h.Get, guard.Read())
	api.PUT("/:id", h.Update, guard.Update())
	api.DELETE("/:id", h.Delete, guard.Delete())
	api.PUT("/:id/activate", h.Activate, guard.Update())
	api.PUT("/:id/deactivate", h.Deactivate, guard.Update())
}

type CreateWorkflowInstanceRequest struct {
	WorkflowDefinitionID *uuid.UUID `json:"workflow-definition-id" validate:"required"`
	Name                 string     `json:"name" validate:"required"`
	Description          string     `json:"description"`
	SystemSecurityPlanID string     `json:"system-id" validate:"required"`
	Cadence              string     `json:"cadence"`
	IsActive             *bool      `json:"is-active"`
	GracePeriodDays      *int       `json:"grace-period-days"`
}

type UpdateWorkflowInstanceRequest struct {
	Name            *string `json:"name"`
	Description     *string `json:"description"`
	Cadence         *string `json:"cadence"`
	IsActive        *bool   `json:"is-active"`
	GracePeriodDays *int    `json:"grace-period-days"`
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
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}
	systemId, err := uuid.Parse(req.SystemSecurityPlanID)
	if err != nil {
		h.sugar.Errorw("Failed to parse system security plan ID", "error", err)
		return h.HandleServiceError(ctx, err, "parse", "system security plan ID")
	}

	actorID, _, err := h.GetActorFromClaims(ctx, h.db)
	if err != nil {
		return HandleError(err)
	}

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: req.WorkflowDefinitionID,
		Name:                 req.Name,
		Description:          req.Description,
		SystemSecurityPlanID: &systemId,
		Cadence:              req.Cadence,
		IsActive:             true, // Default to active
		GracePeriodDays:      req.GracePeriodDays,
		CreatedByID:          actorID,
	}

	if req.IsActive != nil {
		instance.IsActive = *req.IsActive
	}

	if err := h.service.Create(instance); err != nil {
		return h.HandleServiceError(ctx, err, "create", "workflow instance")
	}

	h.sugar.Infow("Workflow instance created", "id", instance.ID)
	return h.RespondCreated(ctx, WorkflowInstanceResponse{Data: instance})
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
			return h.HandleServiceError(ctx, parseErr, "parse", "workflow definition ID")
		}
		filters["workflow_definition_id"] = workflowDefID
	}
	if systemSecurityPlanIDStr != "" {
		systemSecurityPlanID, parseErr := uuid.Parse(systemSecurityPlanIDStr)
		if parseErr != nil {
			return h.HandleServiceError(ctx, parseErr, "parse", "system security plan ID")
		}
		filters["system_security_plan_id"] = systemSecurityPlanID
	}

	instances, _, err = h.service.GetAll(1000, 0, filters)

	if err != nil {
		return h.HandleServiceError(ctx, err, "list", "workflow instances")
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

	return h.RespondOK(ctx, WorkflowInstanceListResponse{Data: instances})
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
	id, err := h.ParseUUID(ctx, "id", "workflow instance")
	if err != nil {
		return HandleError(err)
	}

	instance, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow instance")
	}

	return h.RespondOK(ctx, WorkflowInstanceResponse{Data: instance})
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
	id, err := h.ParseUUID(ctx, "id", "workflow instance")
	if err != nil {
		return HandleError(err)
	}

	var req UpdateWorkflowInstanceRequest
	if err := h.Bind(ctx, &req); err != nil {
		return HandleError(err)
	}

	actorID, _, err := h.GetActorFromClaims(ctx, h.db)
	if err != nil {
		return HandleError(err)
	}

	instance, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow instance")
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
	if req.GracePeriodDays != nil {
		instance.GracePeriodDays = req.GracePeriodDays
	}
	instance.UpdatedByID = actorID

	if err := h.service.Update(id, instance); err != nil {
		return h.HandleServiceError(ctx, err, "update", "workflow instance")
	}

	h.sugar.Infow("Workflow instance updated", "id", instance.ID)
	return h.RespondOK(ctx, WorkflowInstanceResponse{Data: instance})
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
	id, err := h.ParseUUID(ctx, "id", "workflow instance")
	if err != nil {
		return HandleError(err)
	}

	if err := h.service.Delete(id); err != nil {
		return h.HandleServiceError(ctx, err, "delete", "workflow instance")
	}

	h.sugar.Infow("Workflow instance deleted", "id", id)
	return h.RespondNoContent(ctx)
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
	id, err := h.ParseUUID(ctx, "id", "workflow instance")
	if err != nil {
		return HandleError(err)
	}

	// Check if instance exists first
	_, err = h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow instance")
	}

	if err := h.service.Activate(id); err != nil {
		return h.HandleServiceError(ctx, err, "activate", "workflow instance")
	}

	instance, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow instance after activation")
	}

	h.sugar.Infow("Workflow instance activated", "id", id)
	return h.RespondOK(ctx, WorkflowInstanceResponse{Data: instance})
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
	id, err := h.ParseUUID(ctx, "id", "workflow instance")
	if err != nil {
		return HandleError(err)
	}

	// Check if instance exists first
	_, err = h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow instance")
	}

	if err := h.service.Deactivate(id); err != nil {
		return h.HandleServiceError(ctx, err, "deactivate", "workflow instance")
	}

	instance, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow instance after deactivation")
	}

	h.sugar.Infow("Workflow instance deactivated", "id", id)
	return h.RespondOK(ctx, WorkflowInstanceResponse{Data: instance})
}
