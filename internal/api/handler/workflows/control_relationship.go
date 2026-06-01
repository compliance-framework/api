package workflows

import (
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ControlRelationshipHandler struct {
	*BaseHandler
	db         *gorm.DB
	service    *workflows.ControlRelationshipService
	filterSync *workflows.FilterSyncService
}

func NewControlRelationshipHandler(sugar *zap.SugaredLogger, db *gorm.DB) *ControlRelationshipHandler {
	return &ControlRelationshipHandler{
		BaseHandler: NewBaseHandler(sugar),
		db:          db,
		service:     workflows.NewControlRelationshipService(db),
		filterSync:  workflows.NewFilterSyncService(db, sugar),
	}
}

func (h *ControlRelationshipHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
	api.PUT("/:id/activate", h.Activate)
	api.PUT("/:id/deactivate", h.Deactivate)
}

type CreateControlRelationshipRequest struct {
	WorkflowDefinitionID *uuid.UUID `json:"workflow-definition-id" validate:"required"`
	ControlID            string     `json:"control-id" validate:"required"`
	CatalogID            string     `json:"catalog-id" validate:"required"`
	RelationshipType     string     `json:"relationship-type"` // If not provided - 'satisfies' is used
	Strength             string     `json:"strength"`          // If not provided - 'primary' is used
	Description          string     `json:"description"`
	IsActive             *bool      `json:"is-active"`
}

type UpdateControlRelationshipRequest struct {
	RelationshipType *string `json:"relationship-type"`
	Strength         *string `json:"strength"`
	Description      *string `json:"description"`
}

type ControlRelationshipResponse struct {
	Data *workflows.ControlRelationship `json:"data"`
}

type ControlRelationshipListResponse struct {
	Data []workflows.ControlRelationship `json:"data"`
}

// Create godoc
//
//	@Summary		Create control relationship
//	@Description	Create a new control relationship for a workflow
//	@Tags			Control Relationships
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateControlRelationshipRequest	true	"Control relationship details"
//	@Success		201		{object}	ControlRelationshipResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/control-relationships [post]
func (h *ControlRelationshipHandler) Create(ctx echo.Context) error {
	var req CreateControlRelationshipRequest
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}
	relType := req.RelationshipType
	if relType == "" {
		relType = "satisfies"
	}

	strength := req.Strength
	if strength == "" {
		strength = "primary"
	}
	relationship := &workflows.ControlRelationship{
		WorkflowDefinitionID: req.WorkflowDefinitionID,
		ControlID:            req.ControlID,
		CatalogID:            req.CatalogID,
		RelationshipType:     relType,
		Strength:             strength,
		IsActive:             true,
	}

	if catalogUUID, catalogErr := uuid.Parse(req.CatalogID); catalogErr == nil {
		var catalog relational.Catalog
		err := h.db.Preload("Metadata").First(&catalog, "id = ?", catalogUUID).Error
		if err != nil {
			return h.HandleServiceError(ctx, err, "get", "catalog")
		}
		if catalog.Metadata.Title != "" {
			relationship.ControlSource = catalog.Metadata.Title
		}
	}

	if req.IsActive != nil {
		relationship.IsActive = *req.IsActive
	}

	if err := h.service.Create(relationship); err != nil {
		return h.HandleServiceError(ctx, err, "create", "control relationship")
	}
	if err := h.filterSync.SyncFilterForDefinition(*relationship.WorkflowDefinitionID); err != nil {
		return h.HandleServiceError(ctx, err, "sync", "workflow filter")
	}

	h.sugar.Infow("Control relationship created", "id", relationship.ID)
	return h.RespondCreated(ctx, ControlRelationshipResponse{Data: relationship})
}

// List godoc
//
//	@Summary		List control relationships
//	@Description	List all control relationships, optionally filtered by workflow definition
//	@Tags			Control Relationships
//	@Produce		json
//	@Param			workflow_definition_id	query		string	false	"Workflow Definition ID"
//	@Param			control_id				query		string	false	"Control ID"
//	@Success		200						{object}	ControlRelationshipListResponse
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/control-relationships [get]
func (h *ControlRelationshipHandler) List(ctx echo.Context) error {
	workflowDefIDStr := ctx.QueryParam("workflow_definition_id")
	controlID := ctx.QueryParam("control_id")

	var relationships []workflows.ControlRelationship
	var err error

	if workflowDefIDStr != "" {
		workflowDefID, parseErr := uuid.Parse(workflowDefIDStr)
		if parseErr != nil {
			return h.HandleServiceError(ctx, parseErr, "parse", "workflow definition ID")
		}
		relationships, err = h.service.GetByWorkflowDefinitionID(&workflowDefID)
	} else if controlID != "" {
		relationships, err = h.service.GetByControlID(controlID)
	} else {
		// Get all relationships - service doesn't have GetAll, use GetByWorkflowDefinitionID with nil
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_definition_id or control_id is required")))
	}

	if err != nil {
		return h.HandleServiceError(ctx, err, "list", "control relationships")
	}

	return h.RespondOK(ctx, ControlRelationshipListResponse{Data: relationships})
}

// Get godoc
//
//	@Summary		Get control relationship
//	@Description	Get control relationship by ID
//	@Tags			Control Relationships
//	@Produce		json
//	@Param			id	path		string	true	"Control Relationship ID"
//	@Success		200	{object}	ControlRelationshipResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/control-relationships/{id} [get]
func (h *ControlRelationshipHandler) Get(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "control relationship")
	if err != nil {
		return HandleError(err)
	}

	relationship, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "control relationship")
	}

	return h.RespondOK(ctx, ControlRelationshipResponse{Data: relationship})
}

// Update godoc
//
//	@Summary		Update control relationship
//	@Description	Update an existing control relationship
//	@Tags			Control Relationships
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"Control Relationship ID"
//	@Param			request	body		UpdateControlRelationshipRequest	true	"Update details"
//	@Success		200		{object}	ControlRelationshipResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/control-relationships/{id} [put]
func (h *ControlRelationshipHandler) Update(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "control relationship")
	if err != nil {
		return HandleError(err)
	}

	var req UpdateControlRelationshipRequest
	if err := h.Bind(ctx, &req); err != nil {
		return HandleError(err)
	}

	// Build updates map with only provided fields
	updates := make(map[string]interface{})
	if req.RelationshipType != nil {
		updates["relationship_type"] = *req.RelationshipType
	}
	if req.Strength != nil {
		updates["strength"] = *req.Strength
	}

	// Use DB directly for partial updates
	if len(updates) > 0 {
		if err := h.db.Model(&workflows.ControlRelationship{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return h.HandleServiceError(ctx, err, "update", "control relationship")
		}
	}

	relationship, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "control relationship after update")
	}
	if err := h.filterSync.SyncFilterForDefinition(*relationship.WorkflowDefinitionID); err != nil {
		return h.HandleServiceError(ctx, err, "sync", "workflow filter")
	}

	h.sugar.Infow("Control relationship updated", "id", id)
	return h.RespondOK(ctx, ControlRelationshipResponse{Data: relationship})
}

// Delete godoc
//
//	@Summary		Delete control relationship
//	@Description	Delete a control relationship
//	@Tags			Control Relationships
//	@Param			id	path	string	true	"Control Relationship ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/control-relationships/{id} [delete]
func (h *ControlRelationshipHandler) Delete(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "control relationship")
	if err != nil {
		return HandleError(err)
	}

	relationship, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "control relationship")
	}

	if err := h.service.Delete(id); err != nil {
		return h.HandleServiceError(ctx, err, "delete", "control relationship")
	}
	if err := h.filterSync.SyncFilterForDefinition(*relationship.WorkflowDefinitionID); err != nil {
		return h.HandleServiceError(ctx, err, "sync", "workflow filter")
	}

	h.sugar.Infow("Control relationship deleted", "id", id)
	return h.RespondNoContent(ctx)
}

// Activate godoc
//
//	@Summary		Activate control relationship
//	@Description	Activate a control relationship
//	@Tags			Control Relationships
//	@Produce		json
//	@Param			id	path		string	true	"Control Relationship ID"
//	@Success		200	{object}	ControlRelationshipResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/control-relationships/{id}/activate [put]
func (h *ControlRelationshipHandler) Activate(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "control relationship")
	if err != nil {
		return HandleError(err)
	}

	// Check if relationship exists first
	existing, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "control relationship")
	}

	if err := h.service.Activate(id); err != nil {
		return h.HandleServiceError(ctx, err, "activate", "control relationship")
	}

	relationship, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "control relationship after activation")
	}
	if err := h.filterSync.SyncFilterForDefinition(*existing.WorkflowDefinitionID); err != nil {
		return h.HandleServiceError(ctx, err, "sync", "workflow filter")
	}

	h.sugar.Infow("Control relationship activated", "id", id)
	return h.RespondOK(ctx, ControlRelationshipResponse{Data: relationship})
}

// Deactivate godoc
//
//	@Summary		Deactivate control relationship
//	@Description	Deactivate a control relationship
//	@Tags			Control Relationships
//	@Produce		json
//	@Param			id	path		string	true	"Control Relationship ID"
//	@Success		200	{object}	ControlRelationshipResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/control-relationships/{id}/deactivate [put]
func (h *ControlRelationshipHandler) Deactivate(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "control relationship")
	if err != nil {
		return HandleError(err)
	}

	// Check if relationship exists first
	existing, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "control relationship")
	}

	if err := h.service.Deactivate(id); err != nil {
		return h.HandleServiceError(ctx, err, "deactivate", "control relationship")
	}

	relationship, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "control relationship after deactivation")
	}
	if err := h.filterSync.SyncFilterForDefinition(*existing.WorkflowDefinitionID); err != nil {
		return h.HandleServiceError(ctx, err, "sync", "workflow filter")
	}

	h.sugar.Infow("Control relationship deactivated", "id", id)
	return h.RespondOK(ctx, ControlRelationshipResponse{Data: relationship})
}
