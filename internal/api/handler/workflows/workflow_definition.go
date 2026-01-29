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

// isNotFoundError checks if an error is a "not found" error
func isNotFoundError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

type WorkflowDefinitionHandler struct {
	sugar   *zap.SugaredLogger
	service *workflows.WorkflowDefinitionService
}

func NewWorkflowDefinitionHandler(sugar *zap.SugaredLogger, db *gorm.DB) *WorkflowDefinitionHandler {
	return &WorkflowDefinitionHandler{
		sugar:   sugar,
		service: workflows.NewWorkflowDefinitionService(db),
	}
}

func (h *WorkflowDefinitionHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("", h.List)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)
}

type CreateWorkflowDefinitionRequest struct {
	Name             string `json:"name" validate:"required"`
	Description      string `json:"description"`
	Version          string `json:"version"`
	SuggestedCadence string `json:"suggested_cadence"`
	EvidenceRequired string `json:"evidence_required"`
}

type UpdateWorkflowDefinitionRequest struct {
	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Version          *string `json:"version"`
	SuggestedCadence *string `json:"suggested_cadence"`
	EvidenceRequired *string `json:"evidence_required"`
}

type WorkflowDefinitionResponse struct {
	Data *workflows.WorkflowDefinition `json:"data"`
}

type WorkflowDefinitionListResponse struct {
	Data []workflows.WorkflowDefinition `json:"data"`
}

// Create godoc
//
//	@Summary		Create workflow definition
//	@Description	Create a new workflow definition template
//	@Tags			Workflow Definitions
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateWorkflowDefinitionRequest	true	"Workflow definition details"
//	@Success		201		{object}	WorkflowDefinitionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/definitions [post]
func (h *WorkflowDefinitionHandler) Create(ctx echo.Context) error {
	var req CreateWorkflowDefinitionRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := ctx.Validate(&req); err != nil {
		h.sugar.Errorw("Failed to validate request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definition := &workflows.WorkflowDefinition{
		Name:             req.Name,
		Description:      req.Description,
		Version:          req.Version,
		SuggestedCadence: req.SuggestedCadence,
		EvidenceRequired: req.EvidenceRequired,
	}

	if err := h.service.Create(definition); err != nil {
		h.sugar.Errorw("Failed to create workflow definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow definition created", "id", definition.ID)
	return ctx.JSON(http.StatusCreated, WorkflowDefinitionResponse{Data: definition})
}

// List godoc
//
//	@Summary		List workflow definitions
//	@Description	List all workflow definition templates
//	@Tags			Workflow Definitions
//	@Produce		json
//	@Success		200	{object}	WorkflowDefinitionListResponse
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/definitions [get]
func (h *WorkflowDefinitionHandler) List(ctx echo.Context) error {
	// For now, return all definitions without pagination
	// TODO: Add pagination query parameters
	definitions, _, err := h.service.GetAll(1000, 0)
	if err != nil {
		h.sugar.Errorw("Failed to list workflow definitions", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowDefinitionListResponse{Data: definitions})
}

// Get godoc
//
//	@Summary		Get workflow definition
//	@Description	Get workflow definition by ID
//	@Tags			Workflow Definitions
//	@Produce		json
//	@Param			id	path		string	true	"Workflow Definition ID"
//	@Success		200	{object}	WorkflowDefinitionResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/definitions/{id} [get]
func (h *WorkflowDefinitionHandler) Get(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definition, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, WorkflowDefinitionResponse{Data: definition})
}

// Update godoc
//
//	@Summary		Update workflow definition
//	@Description	Update workflow definition by ID
//	@Tags			Workflow Definitions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"Workflow Definition ID"
//	@Param			request	body		UpdateWorkflowDefinitionRequest	true	"Updated workflow definition details"
//	@Success		200		{object}	WorkflowDefinitionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/definitions/{id} [put]
func (h *WorkflowDefinitionHandler) Update(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req UpdateWorkflowDefinitionRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definition, err := h.service.GetByID(&id)
	if err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get workflow definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if req.Name != nil {
		definition.Name = *req.Name
	}
	if req.Description != nil {
		definition.Description = *req.Description
	}
	if req.Version != nil {
		definition.Version = *req.Version
	}
	if req.SuggestedCadence != nil {
		definition.SuggestedCadence = *req.SuggestedCadence
	}
	if req.EvidenceRequired != nil {
		definition.EvidenceRequired = *req.EvidenceRequired
	}

	if err := h.service.Update(&id, definition); err != nil {
		h.sugar.Errorw("Failed to update workflow definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow definition updated", "id", definition.ID)
	return ctx.JSON(http.StatusOK, WorkflowDefinitionResponse{Data: definition})
}

// Delete godoc
//
//	@Summary		Delete workflow definition
//	@Description	Delete workflow definition by ID
//	@Tags			Workflow Definitions
//	@Produce		json
//	@Param			id	path	string	true	"Workflow Definition ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/definitions/{id} [delete]
func (h *WorkflowDefinitionHandler) Delete(ctx echo.Context) error {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.sugar.Errorw("Invalid workflow definition ID", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.Delete(&id); err != nil {
		if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to delete workflow definition", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Workflow definition deleted", "id", id)
	return ctx.NoContent(http.StatusNoContent)
}
