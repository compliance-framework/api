package templates

import (
	"fmt"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type SubjectTemplateHandler struct {
	service    *templaterel.SubjectTemplateService
	sugar      *zap.SugaredLogger
	pagination *svc.PaginationConfig
}

func NewSubjectTemplateHandler(sugar *zap.SugaredLogger, db *gorm.DB) *SubjectTemplateHandler {
	return &SubjectTemplateHandler{
		service:    templaterel.NewSubjectTemplateService(db),
		sugar:      sugar,
		pagination: svc.NewPaginationConfig(),
	}
}

func (h *SubjectTemplateHandler) Register(apiGroup *echo.Group) {
	apiGroup.GET("", h.List)
	apiGroup.POST("", h.Create)
	apiGroup.GET("/:id", h.Get)
	apiGroup.PUT("/:id", h.Update)
}

type subjectTemplateSelectorLabelRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type subjectTemplateLabelSchemaFieldRequest struct {
	Key         string  `json:"key"`
	Description *string `json:"description"`
}

type upsertSubjectTemplateRequest struct {
	Name                string                                   `json:"name" validate:"required"`
	Type                string                                   `json:"type" validate:"required"`
	TitleTemplate       *string                                  `json:"title-template"`
	DescriptionTemplate *string                                  `json:"description-template"`
	PurposeTemplate     *string                                  `json:"purpose-template"`
	RemarksTemplate     *string                                  `json:"remarks-template"`
	IdentityLabelKeys   []string                                 `json:"identity-label-keys" validate:"required"`
	Props               []relational.Prop                        `json:"props"`
	Links               []relational.Link                        `json:"links"`
	SourceMode          string                                   `json:"source-mode" validate:"required"`
	SelectorLabels      []subjectTemplateSelectorLabelRequest    `json:"selector-labels" validate:"required"`
	LabelSchema         []subjectTemplateLabelSchemaFieldRequest `json:"label-schema" validate:"required"`
}

type subjectTemplateSelectorLabelResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type subjectTemplateLabelSchemaFieldResponse struct {
	Key         string  `json:"key"`
	Description *string `json:"description"`
}

type subjectTemplateResponse struct {
	ID                  uuid.UUID                                 `json:"id"`
	CreatedAt           time.Time                                 `json:"createdAt"`
	UpdatedAt           time.Time                                 `json:"updatedAt"`
	Name                string                                    `json:"name"`
	Type                string                                    `json:"type"`
	TitleTemplate       *string                                   `json:"title-template"`
	DescriptionTemplate *string                                   `json:"description-template"`
	PurposeTemplate     *string                                   `json:"purpose-template"`
	RemarksTemplate     *string                                   `json:"remarks-template"`
	IdentityLabelKeys   []string                                  `json:"identity-label-keys"`
	Props               []relational.Prop                         `json:"props"`
	Links               []relational.Link                         `json:"links"`
	SourceMode          string                                    `json:"source-mode"`
	SelectorLabels      []subjectTemplateSelectorLabelResponse    `json:"selector-labels"`
	LabelSchema         []subjectTemplateLabelSchemaFieldResponse `json:"label-schema"`
}

type subjectTemplateDataResponse struct {
	Data subjectTemplateResponse `json:"data"`
}

// List godoc
//
//	@Summary		List subject templates
//	@Description	List subject templates with optional filters and pagination.
//	@Tags			Subject Templates
//	@Produce		json
//	@Param			type		query		string	false	"Subject type"
//	@Param			source-mode	query		string	false	"Source mode"
//	@Param			page		query		int		false	"Page number"
//	@Param			limit		query		int		false	"Page size"
//	@Success		200			{object}	svc.ListResponse[subjectTemplateResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/subject-templates [get]
func (h *SubjectTemplateHandler) List(ctx echo.Context) error {
	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	filters := templaterel.SubjectTemplateListFilters{}
	if templateType := ctx.QueryParam("type"); templateType != "" {
		if !templaterel.IsValidSubjectTemplateType(templateType) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid type filter %q", templateType)))
		}
		filters.Type = &templateType
	}
	if sourceMode := ctx.QueryParam("source-mode"); sourceMode != "" {
		if !templaterel.IsValidSubjectTemplateSourceMode(sourceMode) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid sourceMode filter %q", sourceMode)))
		}
		filters.SourceMode = &sourceMode
	}

	rows, total, err := h.service.List(templaterel.SubjectTemplateListParams{
		Filters: filters,
		Limit:   pagination.Limit,
		Offset:  pagination.Offset,
	})
	if err != nil {
		return templateInternalServerError(ctx, h.sugar, "failed to list subject templates", err)
	}

	resp := make([]subjectTemplateResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, mapSubjectTemplateToResponse(row))
	}

	return ctx.JSON(http.StatusOK, svc.NewListResponse(resp, total, pagination.Page, pagination.Limit))
}

// Create godoc
//
//	@Summary		Create subject template
//	@Description	Create a subject template with selector labels and label schema.
//	@Tags			Subject Templates
//	@Accept			json
//	@Produce		json
//	@Param			template	body		upsertSubjectTemplateRequest	true	"Subject template payload"
//	@Success		201			{object}	subjectTemplateDataResponse
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/subject-templates [post]
func (h *SubjectTemplateHandler) Create(ctx echo.Context) error {
	var req upsertSubjectTemplateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	payload := mapSubjectTemplateRequestToPayload(req)
	row, err := h.service.Create(payload)
	if err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to create subject template", err)
	}

	return ctx.JSON(http.StatusCreated, subjectTemplateDataResponse{Data: mapSubjectTemplateToResponse(*row)})
}

// Get godoc
//
//	@Summary		Get subject template
//	@Description	Get a subject template by ID.
//	@Tags			Subject Templates
//	@Produce		json
//	@Param			id	path		string	true	"Subject Template ID"
//	@Success		200	{object}	subjectTemplateDataResponse
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/subject-templates/{id} [get]
func (h *SubjectTemplateHandler) Get(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	row, err := h.service.GetByID(id)
	if err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to get subject template", err)
	}

	return ctx.JSON(http.StatusOK, subjectTemplateDataResponse{Data: mapSubjectTemplateToResponse(*row)})
}

// Update godoc
//
//	@Summary		Update subject template
//	@Description	Update a subject template and atomically replace selector labels and label schema.
//	@Tags			Subject Templates
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"Subject Template ID"
//	@Param			template	body		upsertSubjectTemplateRequest	true	"Subject template payload"
//	@Success		200			{object}	subjectTemplateDataResponse
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/subject-templates/{id} [put]
func (h *SubjectTemplateHandler) Update(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req upsertSubjectTemplateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	payload := mapSubjectTemplateRequestToPayload(req)
	row, err := h.service.Update(id, payload)
	if err != nil {
		return handleTemplateServiceError(ctx, h.sugar, "failed to update subject template", err)
	}

	return ctx.JSON(http.StatusOK, subjectTemplateDataResponse{Data: mapSubjectTemplateToResponse(*row)})
}

func mapSubjectTemplateRequestToPayload(req upsertSubjectTemplateRequest) templaterel.SubjectTemplatePayload {
	payload := templaterel.SubjectTemplatePayload{
		Name:                req.Name,
		Type:                req.Type,
		TitleTemplate:       req.TitleTemplate,
		DescriptionTemplate: req.DescriptionTemplate,
		PurposeTemplate:     req.PurposeTemplate,
		RemarksTemplate:     req.RemarksTemplate,
		IdentityLabelKeys:   append([]string{}, req.IdentityLabelKeys...),
		Props:               append([]relational.Prop{}, req.Props...),
		Links:               append([]relational.Link{}, req.Links...),
		SourceMode:          req.SourceMode,
		SelectorLabels:      make([]templaterel.SubjectTemplateSelectorLabelInput, 0, len(req.SelectorLabels)),
		LabelSchema:         make([]templaterel.SubjectTemplateLabelSchemaFieldInput, 0, len(req.LabelSchema)),
	}

	for _, label := range req.SelectorLabels {
		payload.SelectorLabels = append(payload.SelectorLabels, templaterel.SubjectTemplateSelectorLabelInput{
			Key:   label.Key,
			Value: label.Value,
		})
	}
	for _, field := range req.LabelSchema {
		payload.LabelSchema = append(payload.LabelSchema, templaterel.SubjectTemplateLabelSchemaFieldInput{
			Key:         field.Key,
			Description: field.Description,
		})
	}

	return payload
}

func mapSubjectTemplateToResponse(row templaterel.SubjectTemplate) subjectTemplateResponse {
	resp := subjectTemplateResponse{
		ID:                  *row.ID,
		CreatedAt:           row.CreatedAt,
		UpdatedAt:           row.UpdatedAt,
		Name:                row.Name,
		Type:                row.Type,
		TitleTemplate:       row.TitleTemplate,
		DescriptionTemplate: row.DescriptionTemplate,
		PurposeTemplate:     row.PurposeTemplate,
		RemarksTemplate:     row.RemarksTemplate,
		IdentityLabelKeys:   append([]string{}, row.IdentityLabelKeys...),
		Props:               append([]relational.Prop{}, row.Props...),
		Links:               append([]relational.Link{}, row.Links...),
		SourceMode:          row.SourceMode,
		SelectorLabels:      make([]subjectTemplateSelectorLabelResponse, 0, len(row.SelectorLabels)),
		LabelSchema:         make([]subjectTemplateLabelSchemaFieldResponse, 0, len(row.LabelSchema)),
	}

	for _, label := range row.SelectorLabels {
		resp.SelectorLabels = append(resp.SelectorLabels, subjectTemplateSelectorLabelResponse{
			Key:   label.Key,
			Value: label.Value,
		})
	}
	for _, field := range row.LabelSchema {
		resp.LabelSchema = append(resp.LabelSchema, subjectTemplateLabelSchemaFieldResponse{
			Key:         field.Key,
			Description: field.Description,
		})
	}

	return resp
}
