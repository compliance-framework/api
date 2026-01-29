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

type ControlRelationshipHandler struct {
	sugar   *zap.SugaredLogger
	db      *gorm.DB
	service *workflows.ControlRelationshipService
}

func NewControlRelationshipHandler(sugar *zap.SugaredLogger, db *gorm.DB) *ControlRelationshipHandler {
	return &ControlRelationshipHandler{
		sugar:   sugar,
		db:      db,
		service: workflows.NewControlRelationshipService(db),
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
	WorkflowDefinitionID *uuid.UUID `json:"workflow_definition_id" validate:"required"`
	ControlID            string     `json:"control_id" validate:"required"`
	ControlSource        string     `json:"control_source" validate:"required"`
	RelationshipType     string     `json:"relationship_type" validate:"required"`
	Strength             string     `json:"strength"`
	Description          string     `json:"description"`
	IsActive             *bool      `json:"is_active"`
}

type UpdateControlRelationshipRequest struct {
	RelationshipType *string `json:"relationship_type"`
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
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relationship := &workflows.ControlRelationship{
		WorkflowDefinitionID: req.WorkflowDefinitionID,
		ControlID:            req.ControlID,
		ControlSource:        req.ControlSource,
		RelationshipType:     req.RelationshipType,
		Strength:             req.Strength,
		IsActive:             true,
	}

	if req.IsActive != nil {
		relationship.IsActive = *req.IsActive
	}

	if err := h.service.Create(relationship); err != nil {
		h.sugar.Errorw("Failed to create control relationship", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Control relationship created", "id", relationship.ID)
	return ctx.JSON(http.StatusCreated, ControlRelationshipResponse{Data: relationship})
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
			h.sugar.Errorw("Invalid workflow definition ID", "error", parseErr)
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}
		relationships, err = h.service.GetByWorkflowDefinitionID(&workflowDefID)
	} else if controlID != "" {
		relationships, err = h.service.GetByControlID(controlID)
	} else {
		// Get all relationships - service doesn't have GetAll, use GetByWorkflowDefinitionID with nil
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_definition_id or control_id is required")))
	}

	if err != nil {
		h.sugar.Errorw("Failed to list control relationships", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, ControlRelationshipListResponse{Data: relationships})
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
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid control relationship ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relationship, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get control relationship", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, ControlRelationshipResponse{Data: relationship})
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
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid control relationship ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req UpdateControlRelationshipRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
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
			h.sugar.Errorw("Failed to update control relationship", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	relationship, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get control relationship after update", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Control relationship updated", "id", id)
	return ctx.JSON(http.StatusOK, ControlRelationshipResponse{Data: relationship})
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
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid control relationship ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.Delete(&id); err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to delete control relationship", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Control relationship deleted", "id", id)
	return ctx.NoContent(http.StatusNoContent)
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
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid control relationship ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if relationship exists first
	_, err = h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get control relationship", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.service.Activate(&id); err != nil {
		h.sugar.Errorw("Failed to activate control relationship", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	relationship, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get control relationship after activation", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Control relationship activated", "id", id)
	return ctx.JSON(http.StatusOK, ControlRelationshipResponse{Data: relationship})
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
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid control relationship ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if relationship exists first
	_, err = h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get control relationship", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.service.Deactivate(&id); err != nil {
		h.sugar.Errorw("Failed to deactivate control relationship", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	relationship, err := h.service.GetByID(&id)
	if err != nil {
		h.sugar.Errorw("Failed to get control relationship after deactivation", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Control relationship deactivated", "id", id)
	return ctx.JSON(http.StatusOK, ControlRelationshipResponse{Data: relationship})
}
