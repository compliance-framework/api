package workflows

import (
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type WorkflowDefinitionHandler struct {
	*BaseHandler
	service *workflows.WorkflowDefinitionService
}

func NewWorkflowDefinitionHandler(sugar *zap.SugaredLogger, db *gorm.DB) *WorkflowDefinitionHandler {
	return &WorkflowDefinitionHandler{
		BaseHandler: NewBaseHandler(sugar),
		service:     workflows.NewWorkflowDefinitionService(db),
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
	SuggestedCadence string `json:"suggested-cadence"`
	EvidenceRequired string `json:"evidence-required"`
	GracePeriodDays  *int   `json:"grace-period-days"`
}

type UpdateWorkflowDefinitionRequest struct {
	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Version          *string `json:"version"`
	SuggestedCadence *string `json:"suggested-cadence"`
	EvidenceRequired *string `json:"evidence-required"`
	GracePeriodDays  *int    `json:"grace-period-days"`
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
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	definition := &workflows.WorkflowDefinition{
		Name:             req.Name,
		Description:      req.Description,
		Version:          req.Version,
		SuggestedCadence: req.SuggestedCadence,
		EvidenceRequired: req.EvidenceRequired,
		GracePeriodDays:  req.GracePeriodDays,
	}

	if err := h.service.Create(definition); err != nil {
		return h.HandleServiceError(ctx, err, "create", "workflow definition")
	}

	h.sugar.Infow("Workflow definition created", "id", definition.ID)
	return h.RespondCreated(ctx, WorkflowDefinitionResponse{Data: definition})
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
		return h.HandleServiceError(ctx, err, "list", "workflow definitions")
	}

	return h.RespondOK(ctx, WorkflowDefinitionListResponse{Data: definitions})
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
	id, err := h.ParseUUID(ctx, "id", "workflow definition")
	if err != nil {
		return HandleError(err)
	}

	definition, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow definition")
	}

	return h.RespondOK(ctx, WorkflowDefinitionResponse{Data: definition})
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
	id, err := h.ParseUUID(ctx, "id", "workflow definition")
	if err != nil {
		return HandleError(err)
	}

	var req UpdateWorkflowDefinitionRequest
	if err := h.Bind(ctx, &req); err != nil {
		return HandleError(err)
	}

	definition, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "workflow definition")
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
	if req.GracePeriodDays != nil {
		definition.GracePeriodDays = req.GracePeriodDays
	}

	if err := h.service.Update(id, definition); err != nil {
		return h.HandleServiceError(ctx, err, "update", "workflow definition")
	}

	h.sugar.Infow("Workflow definition updated", "id", definition.ID)
	return h.RespondOK(ctx, WorkflowDefinitionResponse{Data: definition})
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
	id, err := h.ParseUUID(ctx, "id", "workflow definition")
	if err != nil {
		return HandleError(err)
	}

	if err := h.service.Delete(id); err != nil {
		return h.HandleServiceError(ctx, err, "delete", "workflow definition")
	}

	h.sugar.Infow("Workflow definition deleted", "id", id)
	return h.RespondNoContent(ctx)
}
