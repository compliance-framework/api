package templates

import (
	"errors"
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

type threatIDRequest struct {
	System string  `json:"system"`
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	URL    *string `json:"url"`
}

type remediationTaskRequest struct {
	Title      string `json:"title"`
	OrderIndex int    `json:"orderIndex"`
}

type remediationTemplateRequest struct {
	Title       string                   `json:"title"`
	Description *string                  `json:"description"`
	Tasks       []remediationTaskRequest `json:"tasks"`
}

type upsertRiskTemplateRequest struct {
	PluginID       string                      `json:"pluginId"`
	PolicyPackage  string                      `json:"policyPackage"`
	Name           string                      `json:"name"`
	Title          string                      `json:"title"`
	Statement      string                      `json:"statement"`
	LikelihoodHint *string                     `json:"likelihoodHint"`
	ImpactHint     *string                     `json:"impactHint"`
	ViolationIDs   []string                    `json:"violationIds"`
	ThreatIDs      []threatIDRequest           `json:"threatIds"`
	Remediation    *remediationTemplateRequest `json:"remediationTemplate"`
	IsActive       *bool                       `json:"isActive"`
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
	OrderIndex int       `json:"orderIndex"`
}

type remediationTemplateResponse struct {
	ID          uuid.UUID                 `json:"id"`
	Title       string                    `json:"title"`
	Description *string                   `json:"description"`
	Tasks       []remediationTaskResponse `json:"tasks"`
}

type riskTemplateResponse struct {
	ID             uuid.UUID                    `json:"id"`
	CreatedAt      time.Time                    `json:"createdAt"`
	UpdatedAt      time.Time                    `json:"updatedAt"`
	PluginID       string                       `json:"pluginId"`
	PolicyPackage  string                       `json:"policyPackage"`
	Name           string                       `json:"name"`
	Title          string                       `json:"title"`
	Statement      string                       `json:"statement"`
	LikelihoodHint *string                      `json:"likelihoodHint"`
	ImpactHint     *string                      `json:"impactHint"`
	ViolationIDs   []string                     `json:"violationIds"`
	ThreatIDs      []threatIDResponse           `json:"threatIds"`
	Remediation    *remediationTemplateResponse `json:"remediationTemplate,omitempty"`
	IsActive       bool                         `json:"isActive"`
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
//	@Param			pluginId		query		string	false	"Plugin ID"
//	@Param			policyPackage	query		string	false	"Policy package"
//	@Param			isActive		query		bool	false	"Active flag"
//	@Param			page			query		int		false	"Page number"
//	@Param			limit			query		int		false	"Page size"
//	@Success		200				{object}	svc.ListResponse[riskTemplateResponse]
//	@Failure		400				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risk-templates [get]
func (h *RiskTemplateHandler) List(ctx echo.Context) error {
	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	filters := templaterel.RiskTemplateListFilters{}
	if pluginID := ctx.QueryParam("pluginId"); pluginID != "" {
		filters.PluginID = &pluginID
	}
	if policyPackage := ctx.QueryParam("policyPackage"); policyPackage != "" {
		filters.PolicyPackage = &policyPackage
	}
	if rawIsActive := ctx.QueryParam("isActive"); rawIsActive != "" {
		parsed, parseErr := strconv.ParseBool(rawIsActive)
		if parseErr != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid isActive filter")))
		}
		filters.IsActive = &parsed
	}

	rows, total, err := h.service.List(templaterel.RiskTemplateListParams{
		Filters: filters,
		Limit:   pagination.Limit,
		Offset:  pagination.Offset,
	})
	if err != nil {
		return h.internalServerError(ctx, "failed to list risk templates", err)
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
//	@Router			/risk-templates [post]
func (h *RiskTemplateHandler) Create(ctx echo.Context) error {
	var req upsertRiskTemplateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	payload := mapRequestToPayload(req)

	row, err := h.service.Create(payload)
	if err != nil {
		return h.handleServiceError(ctx, "failed to create risk template", err)
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
//	@Router			/risk-templates/{id} [get]
func (h *RiskTemplateHandler) Get(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	row, err := h.service.GetByID(id)
	if err != nil {
		return h.handleServiceError(ctx, "failed to get risk template", err)
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
//	@Router			/risk-templates/{id} [put]
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
		return h.handleServiceError(ctx, "failed to update risk template", err)
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
//	@Router			/risk-templates/{id} [delete]
func (h *RiskTemplateHandler) Delete(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.service.Delete(id); err != nil {
		return h.handleServiceError(ctx, "failed to delete risk template", err)
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (h *RiskTemplateHandler) handleServiceError(ctx echo.Context, message string, err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}
	if templaterel.IsValidationError(err) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return h.internalServerError(ctx, message, err)
}

func (h *RiskTemplateHandler) internalServerError(ctx echo.Context, message string, err error) error {
	if h.sugar != nil {
		h.sugar.Errorw(message, "error", err)
	}
	return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("internal server error")))
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
