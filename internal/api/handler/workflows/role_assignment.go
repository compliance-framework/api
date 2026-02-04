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

type RoleAssignmentHandler struct {
	*BaseHandler
	db      *gorm.DB
	service *workflows.RoleAssignmentService
}

func NewRoleAssignmentHandler(sugar *zap.SugaredLogger, db *gorm.DB) *RoleAssignmentHandler {
	return &RoleAssignmentHandler{
		BaseHandler: NewBaseHandler(sugar),
		db:          db,
		service:     workflows.NewRoleAssignmentService(db),
	}
}

func (h *RoleAssignmentHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
	api.PUT("/:id/activate", h.Activate)
	api.PUT("/:id/deactivate", h.Deactivate)
}

type CreateRoleAssignmentRequest struct {
	WorkflowInstanceID *uuid.UUID `json:"workflow-instance-id" validate:"required"`
	RoleName           string     `json:"role-name" validate:"required"`
	AssignedToType     string     `json:"assigned-to-type" validate:"required"`
	AssignedToID       string     `json:"assigned-to-id" validate:"required"`
	IsActive           *bool      `json:"is-active"`
}

type UpdateRoleAssignmentRequest struct {
	AssignedToType *string `json:"assigned-to-type"`
	AssignedToID   *string `json:"assigned-to-id"`
}

type RoleAssignmentResponse struct {
	Data *workflows.RoleAssignment `json:"data"`
}

type RoleAssignmentListResponse struct {
	Data []workflows.RoleAssignment `json:"data"`
}

// Create godoc
//
//	@Summary		Create role assignment
//	@Description	Create a new role assignment for a workflow instance
//	@Tags			Role Assignments
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateRoleAssignmentRequest	true	"Role assignment details"
//	@Success		201		{object}	RoleAssignmentResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/role-assignments [post]
func (h *RoleAssignmentHandler) Create(ctx echo.Context) error {
	var req CreateRoleAssignmentRequest
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	assignment := &workflows.RoleAssignment{
		WorkflowInstanceID: req.WorkflowInstanceID,
		RoleName:           req.RoleName,
		AssignedToType:     req.AssignedToType,
		AssignedToID:       req.AssignedToID,
		IsActive:           true,
	}

	if req.IsActive != nil {
		assignment.IsActive = *req.IsActive
	}

	if err := h.service.Create(assignment); err != nil {
		return h.HandleServiceError(ctx, err, "create", "role assignment")
	}

	h.sugar.Infow("Role assignment created", "id", assignment.ID)
	return h.RespondCreated(ctx, RoleAssignmentResponse{Data: assignment})
}

// List godoc
//
//	@Summary		List role assignments
//	@Description	List all role assignments, optionally filtered by workflow instance
//	@Tags			Role Assignments
//	@Produce		json
//	@Param			workflow_instance_id	query		string	false	"Workflow Instance ID"
//	@Param			role_name				query		string	false	"Role Name"
//	@Success		200						{object}	RoleAssignmentListResponse
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/role-assignments [get]
func (h *RoleAssignmentHandler) List(ctx echo.Context) error {
	workflowInstIDStr := ctx.QueryParam("workflow_instance_id")
	roleName := ctx.QueryParam("role_name")

	if workflowInstIDStr == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_instance_id is required")))
	}

	workflowInstID, parseErr := uuid.Parse(workflowInstIDStr)
	if parseErr != nil {
		return h.HandleServiceError(ctx, parseErr, "parse", "workflow instance ID")
	}

	var assignments []workflows.RoleAssignment
	var err error

	if roleName != "" {
		// Filter by both instance and role
		assignments, err = h.service.GetByRole(&workflowInstID, roleName)
	} else {
		// Get all for instance
		assignments, err = h.service.GetByWorkflowInstanceID(&workflowInstID)
	}

	if err != nil {
		return h.HandleServiceError(ctx, err, "list", "role assignments")
	}

	return h.RespondOK(ctx, RoleAssignmentListResponse{Data: assignments})
}

// Get godoc
//
//	@Summary		Get role assignment
//	@Description	Get role assignment by ID
//	@Tags			Role Assignments
//	@Produce		json
//	@Param			id	path		string	true	"Role Assignment ID"
//	@Success		200	{object}	RoleAssignmentResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/role-assignments/{id} [get]
func (h *RoleAssignmentHandler) Get(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "role assignment")
	if err != nil {
		return HandleError(err)
	}

	assignment, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "role assignment")
	}

	return h.RespondOK(ctx, RoleAssignmentResponse{Data: assignment})
}

// Update godoc
//
//	@Summary		Update role assignment
//	@Description	Update an existing role assignment
//	@Tags			Role Assignments
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"Role Assignment ID"
//	@Param			request	body		UpdateRoleAssignmentRequest	true	"Update details"
//	@Success		200		{object}	RoleAssignmentResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/role-assignments/{id} [put]
func (h *RoleAssignmentHandler) Update(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "role assignment")
	if err != nil {
		return HandleError(err)
	}

	var req UpdateRoleAssignmentRequest
	if err := h.Bind(ctx, &req); err != nil {
		return HandleError(err)
	}

	// Build updates map with only provided fields
	updates := make(map[string]interface{})
	if req.AssignedToType != nil {
		updates["assigned_to_type"] = *req.AssignedToType
	}
	if req.AssignedToID != nil {
		updates["assigned_to_id"] = *req.AssignedToID
	}

	// Use DB directly for partial updates
	if len(updates) > 0 {
		if err := h.db.Model(&workflows.RoleAssignment{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return h.HandleServiceError(ctx, err, "update", "role assignment")
		}
	}

	assignment, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "role assignment after update")
	}

	h.sugar.Infow("Role assignment updated", "id", id)
	return h.RespondOK(ctx, RoleAssignmentResponse{Data: assignment})
}

// Delete godoc
//
//	@Summary		Delete role assignment
//	@Description	Delete a role assignment
//	@Tags			Role Assignments
//	@Param			id	path	string	true	"Role Assignment ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/role-assignments/{id} [delete]
func (h *RoleAssignmentHandler) Delete(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "role assignment")
	if err != nil {
		return HandleError(err)
	}

	if err := h.service.Delete(id); err != nil {
		return h.HandleServiceError(ctx, err, "delete", "role assignment")
	}

	h.sugar.Infow("Role assignment deleted", "id", id)
	return h.RespondNoContent(ctx)
}

// Activate godoc
//
//	@Summary		Activate role assignment
//	@Description	Activate a role assignment
//	@Tags			Role Assignments
//	@Produce		json
//	@Param			id	path		string	true	"Role Assignment ID"
//	@Success		200	{object}	RoleAssignmentResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/role-assignments/{id}/activate [put]
func (h *RoleAssignmentHandler) Activate(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "role assignment")
	if err != nil {
		return HandleError(err)
	}

	// Check if assignment exists first
	_, err = h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "role assignment")
	}

	if err := h.service.Activate(id); err != nil {
		return h.HandleServiceError(ctx, err, "activate", "role assignment")
	}

	assignment, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "role assignment after activation")
	}

	h.sugar.Infow("Role assignment activated", "id", id)
	return h.RespondOK(ctx, RoleAssignmentResponse{Data: assignment})
}

// Deactivate godoc
//
//	@Summary		Deactivate role assignment
//	@Description	Deactivate a role assignment
//	@Tags			Role Assignments
//	@Produce		json
//	@Param			id	path		string	true	"Role Assignment ID"
//	@Success		200	{object}	RoleAssignmentResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/role-assignments/{id}/deactivate [put]
func (h *RoleAssignmentHandler) Deactivate(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "role assignment")
	if err != nil {
		return HandleError(err)
	}

	// Check if assignment exists first
	_, err = h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "role assignment")
	}

	if err := h.service.Deactivate(id); err != nil {
		return h.HandleServiceError(ctx, err, "deactivate", "role assignment")
	}

	assignment, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "role assignment after deactivation")
	}

	h.sugar.Infow("Role assignment deactivated", "id", id)
	return h.RespondOK(ctx, RoleAssignmentResponse{Data: assignment})
}
