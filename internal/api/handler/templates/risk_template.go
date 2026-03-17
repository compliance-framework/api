package templates

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/compliance-framework/api/internal/api"
	svc "github.com/compliance-framework/api/internal/service"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type RiskTemplateHandler struct {
	service    *templaterel.RiskTemplateService
	sugar      *zap.SugaredLogger
	pagination *svc.PaginationConfig
}

func NewRiskTemplateHandler(sugar *zap.SugaredLogger, db *gorm.DB) *RiskTemplateHandler {
	return &RiskTemplateHandler{
		service:    templaterel.NewRiskTemplateService(db),
		sugar:      sugar,
		pagination: svc.NewPaginationConfig(),
	}
}

func (h *RiskTemplateHandler) Register(apiGroup *echo.Group) {
	apiGroup.GET("", h.List)
	apiGroup.POST("", h.Create)
	apiGroup.GET("/:id", h.Get)
	apiGroup.PUT("/:id", h.Update)
	apiGroup.DELETE("/:id", h.Delete)
}

func (h *RiskTemplateHandler) RegisterAgent(apiGroup *echo.Group) {
	apiGroup.POST("/batch", h.BatchUpsert)
}

type threatIDRequest struct {
	System string  `json:"system"`
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	URL    *string `json:"url"`
}

type remediationTaskRequest struct {
	Title      string `json:"title"`
	OrderIndex int    `json:"order-index"`
}

type remediationTemplateRequest struct {
	Title       string                   `json:"title"`
	Description *string                  `json:"description"`
	Tasks       []remediationTaskRequest `json:"tasks"`
}

type upsertRiskTemplateRequest struct {
	PluginID       string                      `json:"plugin-id"`
	PolicyPackage  string                      `json:"policy-package"`
	Name           string                      `json:"name"`
	Title          string                      `json:"title"`
	Statement      string                      `json:"statement"`
	LikelihoodHint *string                     `json:"likelihood-hint"`
	ImpactHint     *string                     `json:"impact-hint"`
	ViolationIDs   []string                    `json:"violation-ids"`
	ThreatIDs      []threatIDRequest           `json:"threat-ids"`
	Remediation    *remediationTemplateRequest `json:"remediation-template"`
	IsActive       *bool                       `json:"is-active"`
}

type threatIDResponse struct {
	System string  `json:"system"`
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	URL    *string `json:"url"`
}

type remediationTaskResponse struct {
	ID         uuid.UUID `json:"id"`
	Title      string    `json:"title"`
	OrderIndex int       `json:"order-index"`
}

type remediationTemplateResponse struct {
	ID          uuid.UUID                 `json:"id"`
	Title       string                    `json:"title"`
	Description *string                   `json:"description"`
	Tasks       []remediationTaskResponse `json:"tasks"`
}

type riskTemplateResponse struct {
	ID             uuid.UUID                    `json:"id"`
	CreatedAt      time.Time                    `json:"created-at"`
	UpdatedAt      time.Time                    `json:"updated-at"`
	PluginID       string                       `json:"plugin-id"`
	PolicyPackage  string                       `json:"policy-package"`
	Name           string                       `json:"name"`
	Title          string                       `json:"title"`
	Statement      string                       `json:"statement"`
	LikelihoodHint *string                      `json:"likelihood-hint"`
	ImpactHint     *string                      `json:"impact-hint"`
	ViolationIDs   []string                     `json:"violation-ids"`
	ThreatIDs      []threatIDResponse           `json:"threat-ids"`
	Remediation    *remediationTemplateResponse `json:"remediation-template,omitempty"`
	IsActive       bool                         `json:"is-active"`
}

type riskTemplateDataResponse struct {
	Data riskTemplateResponse `json:"data"`
}

// List godoc
//
//	@Summary		List risk templates
//	@Description	List risk templates with optional filters and pagination.
//	@Tags			Risk Templates
//	@Produce		json
//	@Param			plugin-id		query		string	false	"Plugin ID"
//	@Param			policy-package	query		string	false	"Policy package"
//	@Param			is-active		query		bool	false	"Active flag"
//	@Param			page			query		int		false	"Page number"
//	@Param			limit			query		int		false	"Page size"
//	@Success		200				{object}	svc.ListResponse[riskTemplateResponse]
//	@Failure		400				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/risk-templates [get]
func (h *RiskTemplateHandler) List(ctx echo.Context) error {
	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	filters := templaterel.RiskTemplateListFilters{}
	if pluginID := ctx.QueryParam("plugin-id"); pluginID != "" {
		filters.PluginID = &pluginID
	}
	if policyPackage := ctx.QueryParam("policy-package"); policyPackage != "" {
		filters.PolicyPackage = &policyPackage
	}
	if rawIsActive := ctx.QueryParam("is-active"); rawIsActive != "" {
		parsed, parseErr := strconv.ParseBool(rawIsActive)
		if parseErr != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid is-active filter %q: %w", rawIsActive, parseErr)))
		}
		filters.IsActive = &parsed
	}

	rows, total, err := h.service.List(templaterel.RiskTemplateListParams{
		Filters: filters,
		Limit:   pagination.Limit,
		Offset:  pagination.Offset,
	})
	if err != nil {
		return templateInternalServerError(ctx, h.sugar, "failed to list risk templates", err)
	}

	resp := make([]riskTemplateResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, mapRiskTemplateToResponse(row))
	}

	return ctx.JSON(http.StatusOK, svc.NewListResponse(resp, total, pagination.Page, pagination.Limit))
}

// Create godoc
//
//	@Summary		Create risk template
//	@Description	Create a risk template with threat references and remediation template/tasks.
//	@Tags			Risk Templates
//	@Accept			json
//	@Produce		json
//	@Param			template	body		upsertRiskTemplateRequest	true	"Risk template payload"
//	@Success		201			{object}	riskTemplateDataResponse
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/risk-templates [post]
func (h *RiskTemplateHandler) Create(ctx echo.Context) error {
	var req upsertRiskTemplateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	payload := mapRequestToPayload(req)

	row, err := h.service.Create(payload)
	if err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to create risk template", err)
	}

	return ctx.JSON(http.StatusCreated, riskTemplateDataResponse{Data: mapRiskTemplateToResponse(*row)})
}

// Get godoc
//
//	@Summary		Get risk template
//	@Description	Get a risk template by ID.
//	@Tags			Risk Templates
//	@Produce		json
//	@Param			id	path		string	true	"Risk Template ID"
//	@Success		200	{object}	riskTemplateDataResponse
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/risk-templates/{id} [get]
func (h *RiskTemplateHandler) Get(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	row, err := h.service.GetByID(id)
	if err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to get risk template", err)
	}

	return ctx.JSON(http.StatusOK, riskTemplateDataResponse{Data: mapRiskTemplateToResponse(*row)})
}

// Update godoc
//
//	@Summary		Update risk template
//	@Description	Update a risk template and atomically replace threat refs and remediation tasks.
//	@Tags			Risk Templates
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Risk Template ID"
//	@Param			template	body		upsertRiskTemplateRequest	true	"Risk template payload"
//	@Success		200			{object}	riskTemplateDataResponse
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/risk-templates/{id} [put]
func (h *RiskTemplateHandler) Update(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req upsertRiskTemplateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	payload := mapRequestToPayload(req)

	row, err := h.service.Update(id, payload)
	if err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to update risk template", err)
	}

	return ctx.JSON(http.StatusOK, riskTemplateDataResponse{Data: mapRiskTemplateToResponse(*row)})
}

// Delete godoc
//
//	@Summary		Delete risk template
//	@Description	Delete a risk template and its associated threat references and remediation data.
//	@Tags			Risk Templates
//	@Produce		json
//	@Param			id	path	string	true	"Risk Template ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/risk-templates/{id} [delete]
func (h *RiskTemplateHandler) Delete(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.Delete(id); err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to delete risk template", err)
	}

	return ctx.NoContent(http.StatusNoContent)
}

func mapRequestToPayload(req upsertRiskTemplateRequest) templaterel.RiskTemplatePayload {
	payload := templaterel.RiskTemplatePayload{
		PluginID:       req.PluginID,
		PolicyPackage:  req.PolicyPackage,
		Name:           req.Name,
		Title:          req.Title,
		Statement:      req.Statement,
		LikelihoodHint: req.LikelihoodHint,
		ImpactHint:     req.ImpactHint,
		ViolationIDs:   req.ViolationIDs,
		IsActive:       req.IsActive,
		ThreatRefs:     make([]templaterel.ThreatRefInput, 0, len(req.ThreatIDs)),
	}

	for _, ref := range req.ThreatIDs {
		payload.ThreatRefs = append(payload.ThreatRefs, templaterel.ThreatRefInput{
			System:     ref.System,
			ExternalID: ref.ID,
			Title:      ref.Title,
			URL:        ref.URL,
		})
	}

	if req.Remediation != nil {
		remediation := templaterel.RemediationTemplateInput{
			Title:       req.Remediation.Title,
			Description: req.Remediation.Description,
			Tasks:       make([]templaterel.RemediationTaskInput, 0, len(req.Remediation.Tasks)),
		}
		for _, task := range req.Remediation.Tasks {
			remediation.Tasks = append(remediation.Tasks, templaterel.RemediationTaskInput{
				Title:      task.Title,
				OrderIndex: task.OrderIndex,
			})
		}
		payload.RemediationTemplate = &remediation
	}

	return payload
}

type batchRiskTemplateItem struct {
	ID             string                      `json:"id"`
	Name           string                      `json:"name"`
	Title          string                      `json:"title"`
	Statement      string                      `json:"statement"`
	LikelihoodHint *string                     `json:"likelihood-hint"`
	ImpactHint     *string                     `json:"impact-hint"`
	ViolationIDs   []string                    `json:"violation-ids"`
	ThreatIDs      []threatIDRequest           `json:"threat-ids"`
	Remediation    *remediationTemplateRequest `json:"remediation-template"`
	IsActive       *bool                       `json:"is-active"`
}

type batchUpsertRiskTemplatesRequest struct {
	PluginID      string                   `json:"plugin-id"`
	PolicyPackage string                   `json:"policy-package"`
	Templates     *[]batchRiskTemplateItem `json:"templates"`
}

type batchUpsertRiskTemplatesData struct {
	Created   []riskTemplateResponse `json:"created"`
	Updated   []riskTemplateResponse `json:"updated"`
	Deleted   []uuid.UUID            `json:"deleted"`
	Unchanged []uuid.UUID            `json:"unchanged"`
}

type batchUpsertRiskTemplatesResponse struct {
	Data batchUpsertRiskTemplatesData `json:"data"`
}

// BatchUpsert godoc
//
//	@Summary		Batch upsert risk templates
//	@Description	Reconcile the full set of risk templates for a (plugin-id, policy-package) scope.
//	@Description	Creates, updates, and deletes templates atomically. Templates not present in the payload are always deleted.
//	@Tags			Risk Templates
//	@Accept			json
//	@Produce		json
//	@Param			body	body		batchUpsertRiskTemplatesRequest	true	"Batch upsert payload"
//	@Success		200		{object}	batchUpsertRiskTemplatesResponse
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/agent/risk-templates/batch [post]
func (h *RiskTemplateHandler) BatchUpsert(ctx echo.Context) error {
	var req batchUpsertRiskTemplatesRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.Templates == nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("templates field is required; use [] for an explicit empty list")))
	}

	items := make([]templaterel.BatchRiskTemplateItem, 0, len(*req.Templates))
	for _, item := range *req.Templates {
		if item.ID == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("item %d: id is required", len(items))))
		}
		parsedID, err := uuid.Parse(item.ID)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("item %d: invalid id %q: %w", len(items), item.ID, err)))
		}
		svcItem := templaterel.BatchRiskTemplateItem{
			ID:             parsedID,
			Name:           item.Name,
			Title:          item.Title,
			Statement:      item.Statement,
			LikelihoodHint: item.LikelihoodHint,
			ImpactHint:     item.ImpactHint,
			ViolationIDs:   item.ViolationIDs,
			IsActive:       item.IsActive,
			ThreatRefs:     make([]templaterel.ThreatRefInput, 0, len(item.ThreatIDs)),
		}
		for _, ref := range item.ThreatIDs {
			svcItem.ThreatRefs = append(svcItem.ThreatRefs, templaterel.ThreatRefInput{
				System:     ref.System,
				ExternalID: ref.ID,
				Title:      ref.Title,
				URL:        ref.URL,
			})
		}
		if item.Remediation != nil {
			rem := templaterel.RemediationTemplateInput{
				Title:       item.Remediation.Title,
				Description: item.Remediation.Description,
				Tasks:       make([]templaterel.RemediationTaskInput, 0, len(item.Remediation.Tasks)),
			}
			for _, task := range item.Remediation.Tasks {
				rem.Tasks = append(rem.Tasks, templaterel.RemediationTaskInput{
					Title:      task.Title,
					OrderIndex: task.OrderIndex,
				})
			}
			svcItem.RemediationTemplate = &rem
		}
		items = append(items, svcItem)
	}

	result, err := h.service.BatchUpsert(req.PluginID, req.PolicyPackage, items)
	if err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to batch upsert risk templates", err)
	}

	data := batchUpsertRiskTemplatesData{
		Created:   make([]riskTemplateResponse, 0, len(result.Created)),
		Updated:   make([]riskTemplateResponse, 0, len(result.Updated)),
		Deleted:   result.Deleted,
		Unchanged: result.Unchanged,
	}
	for _, row := range result.Created {
		data.Created = append(data.Created, mapRiskTemplateToResponse(row))
	}
	for _, row := range result.Updated {
		data.Updated = append(data.Updated, mapRiskTemplateToResponse(row))
	}

	return ctx.JSON(http.StatusOK, batchUpsertRiskTemplatesResponse{Data: data})
}

func mapRiskTemplateToResponse(row templaterel.RiskTemplate) riskTemplateResponse {
	resp := riskTemplateResponse{
		ID:             *row.ID,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
		PluginID:       row.PluginID,
		PolicyPackage:  row.PolicyPackage,
		Name:           row.Name,
		Title:          row.Title,
		Statement:      row.Statement,
		LikelihoodHint: row.LikelihoodHint,
		ImpactHint:     row.ImpactHint,
		ViolationIDs:   append([]string{}, row.ViolationIDs...),
		ThreatIDs:      make([]threatIDResponse, 0, len(row.ThreatRefs)),
		IsActive:       row.IsActive,
	}

	for _, ref := range row.ThreatRefs {
		resp.ThreatIDs = append(resp.ThreatIDs, threatIDResponse{
			System: ref.System,
			ID:     ref.ExternalID,
			Title:  ref.Title,
			URL:    ref.URL,
		})
	}

	if row.RemediationTemplate != nil && row.RemediationTemplate.ID != nil {
		remediation := remediationTemplateResponse{
			ID:          *row.RemediationTemplate.ID,
			Title:       row.RemediationTemplate.Title,
			Description: row.RemediationTemplate.Description,
			Tasks:       make([]remediationTaskResponse, 0, len(row.RemediationTemplate.Tasks)),
		}
		for _, task := range row.RemediationTemplate.Tasks {
			if task.ID == nil {
				continue
			}
			remediation.Tasks = append(remediation.Tasks, remediationTaskResponse{
				ID:         *task.ID,
				Title:      task.Title,
				OrderIndex: task.OrderIndex,
			})
		}
		resp.Remediation = &remediation
	}

	return resp
}
