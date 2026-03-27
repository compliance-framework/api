package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	svc "github.com/compliance-framework/api/internal/service"
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type RiskHandler struct {
	riskService *riskrel.RiskService
	poamService *poamsvc.PoamService
	sugar       *zap.SugaredLogger
	pagination  *svc.PaginationConfig
}

const (
	maxRiskTitleLength       = 1000
	maxRiskDescriptionLength = 1000
)

func NewRiskHandler(sugar *zap.SugaredLogger, db *gorm.DB, poamSvc *poamsvc.PoamService, riskSvc *riskrel.RiskService) *RiskHandler {
	return &RiskHandler{
		riskService: riskSvc,
		poamService: poamSvc,
		sugar:       sugar,
		pagination:  svc.NewPaginationConfig(),
	}
}

func (h *RiskHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.POST("", h.Create)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.POST("/:id/accept", h.Accept)
	api.POST("/:id/review", h.Review)
	api.POST("/:id/promote-to-poam", h.PromoteToPoam)
	api.DELETE("/:id", h.Delete)
	api.GET("/:id/events", h.GetEvents)
	api.GET("/:id/reviews", h.GetReviews)

	api.GET("/:id/evidence", h.GetEvidenceLinks)
	api.POST("/:id/evidence", h.AddEvidenceLink)
	api.DELETE("/:id/evidence/:evidenceId", h.DeleteEvidenceLink)

	api.GET("/:id/controls", h.GetControlLinks)
	api.POST("/:id/controls", h.AddControlLink)
	api.DELETE("/:id/controls/:catalogId/:controlId", h.DeleteControlLink)

	api.GET("/:id/components", h.GetComponentLinks)
	api.POST("/:id/components", h.AddComponentLink)
	api.DELETE("/:id/components/:componentId", h.DeleteComponentLink)

	api.GET("/:id/subjects", h.GetSubjectLinks)
	api.POST("/:id/subjects", h.AddSubjectLink)
	api.GET("/:id/threat-ids", h.ListThreatRefs)
	api.POST("/:id/threat-ids", h.AddThreatRef)
	api.GET("/:id/threat-ids/:threatRefId", h.GetThreatRef)
	api.PUT("/:id/threat-ids/:threatRefId", h.UpdateThreatRef)
	api.DELETE("/:id/threat-ids/:threatRefId", h.DeleteThreatRef)
	api.GET("/:id/remediation-template", h.GetRemediationTemplate)
	api.POST("/:id/remediation-template", h.CreateRemediationTemplate)
	api.PUT("/:id/remediation-template", h.UpsertRemediationTemplate)
	api.DELETE("/:id/remediation-template", h.DeleteRemediationTemplate)
}

func (h *RiskHandler) RegisterSSPScoped(api *echo.Group) {
	api.GET("", h.ListForSSP)
	api.POST("", h.CreateForSSP)
	api.GET("/:id", h.GetForSSP)
	api.PUT("/:id", h.UpdateForSSP)
	api.POST("/:id/accept", h.AcceptForSSP)
	api.POST("/:id/review", h.ReviewForSSP)
	api.POST("/:id/promote-to-poam", h.PromoteToPoamForSSP)
	api.DELETE("/:id", h.DeleteForSSP)
	api.GET("/:id/events", h.GetEventsForSSP)
	api.GET("/:id/reviews", h.GetReviewsForSSP)
	api.GET("/:id/evidence", h.GetEvidenceLinksForSSP)
	api.POST("/:id/evidence", h.AddEvidenceLinkForSSP)
	api.DELETE("/:id/evidence/:evidenceId", h.DeleteEvidenceLinkForSSP)

	api.GET("/:id/controls", h.GetControlLinksForSSP)
	api.POST("/:id/controls", h.AddControlLinkForSSP)
	api.DELETE("/:id/controls/:catalogId/:controlId", h.DeleteControlLinkForSSP)

	api.GET("/:id/components", h.GetComponentLinksForSSP)
	api.POST("/:id/components", h.AddComponentLinkForSSP)
	api.DELETE("/:id/components/:componentId", h.DeleteComponentLinkForSSP)
	api.GET("/:id/threat-ids", h.ListThreatRefsForSSP)
	api.POST("/:id/threat-ids", h.AddThreatRefForSSP)
	api.GET("/:id/threat-ids/:threatRefId", h.GetThreatRefForSSP)
	api.PUT("/:id/threat-ids/:threatRefId", h.UpdateThreatRefForSSP)
	api.DELETE("/:id/threat-ids/:threatRefId", h.DeleteThreatRefForSSP)
	api.GET("/:id/remediation-template", h.GetRemediationTemplateForSSP)
	api.POST("/:id/remediation-template", h.CreateRemediationTemplateForSSP)
	api.PUT("/:id/remediation-template", h.UpsertRemediationTemplateForSSP)
	api.DELETE("/:id/remediation-template", h.DeleteRemediationTemplateForSSP)
}

type riskOwnerAssignmentRequest struct {
	OwnerKind string `json:"owner-kind"`
	OwnerRef  string `json:"owner-ref"`
	IsPrimary bool   `json:"is-primary"`
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

type createRiskRequest struct {
	Title                   string                       `json:"title"`
	Description             string                       `json:"description"`
	Status                  *string                      `json:"status"`
	PrimaryOwnerUserID      *uuid.UUID                   `json:"primary-owner-user-id"`
	OwnerAssignments        []riskOwnerAssignmentRequest `json:"owner-assignments"`
	Likelihood              *string                      `json:"likelihood"`
	Impact                  *string                      `json:"impact"`
	SSPID                   uuid.UUID                    `json:"ssp-id"`
	RiskTemplateID          *uuid.UUID                   `json:"risk-template-id"`
	ReviewDeadline          *time.Time                   `json:"review-deadline"`
	LastReviewedAt          *time.Time                   `json:"last-reviewed-at"`
	AcceptanceJustification *string                      `json:"acceptance-justification"`
	ThreatIDs               []threatIDRequest            `json:"threat-ids"`
	Remediation             *remediationTemplateRequest  `json:"remediation-template"`
}

type updateRiskRequest struct {
	Title                   *string                       `json:"title"`
	Description             *string                       `json:"description"`
	Status                  *string                       `json:"status"`
	PrimaryOwnerUserID      *uuid.UUID                    `json:"primary-owner-user-id"`
	OwnerAssignments        *[]riskOwnerAssignmentRequest `json:"owner-assignments"`
	Likelihood              *string                       `json:"likelihood"`
	Impact                  *string                       `json:"impact"`
	RiskTemplateID          *uuid.UUID                    `json:"risk-template-id"`
	ReviewDeadline          *time.Time                    `json:"review-deadline"`
	LastReviewedAt          *time.Time                    `json:"last-reviewed-at"`
	ReviewJustification     *string                       `json:"review-justification"`
	AcceptanceJustification *string                       `json:"acceptance-justification"`
	ThreatIDs               []threatIDRequest             `json:"threat-ids"`
	Remediation             *remediationTemplateRequest   `json:"remediation-template"`
}

type riskOwnerAssignmentResponse struct {
	OwnerKind string `json:"owner-kind"`
	OwnerRef  string `json:"owner-ref"`
	IsPrimary bool   `json:"is-primary"`
}

type riskControlLinkResponse struct {
	CatalogID uuid.UUID `json:"catalog-id"`
	ControlID string    `json:"control-id"`
}

type threatIDResponse struct {
	ID     uuid.UUID `json:"threat-ref-id"`
	System string    `json:"system"`
	RefID  string    `json:"id"`
	Title  string    `json:"title"`
	URL    *string   `json:"url"`
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

type riskResponse struct {
	ID                      uuid.UUID                     `json:"id"`
	CreatedAt               time.Time                     `json:"created-at"`
	UpdatedAt               time.Time                     `json:"updated-at"`
	Title                   string                        `json:"title"`
	Description             string                        `json:"description"`
	Status                  string                        `json:"status"`
	PrimaryOwnerUserID      *uuid.UUID                    `json:"primary-owner-user-id"`
	OwnerAssignments        []riskOwnerAssignmentResponse `json:"owner-assignments"`
	Likelihood              *string                       `json:"likelihood"`
	Impact                  *string                       `json:"impact"`
	SSPID                   uuid.UUID                     `json:"ssp-id"`
	SourceType              string                        `json:"source-type"`
	RiskTemplateID          *uuid.UUID                    `json:"risk-template-id"`
	DedupeKey               string                        `json:"dedupe-key"`
	ReviewDeadline          *time.Time                    `json:"review-deadline"`
	LastReviewedAt          *time.Time                    `json:"last-reviewed-at"`
	AcceptanceJustification *string                       `json:"acceptance-justification"`
	FirstSeenAt             time.Time                     `json:"first-seen-at"`
	LastSeenAt              time.Time                     `json:"last-seen-at"`
	EvidenceIDs             []uuid.UUID                   `json:"evidence-ids"`
	ControlLinks            []riskControlLinkResponse     `json:"control-links"`
	ComponentIDs            []uuid.UUID                   `json:"component-ids"`
	SubjectIDs              []uuid.UUID                   `json:"subject-ids"`
	ThreatIDs               []threatIDResponse            `json:"threat-ids"`
	Remediation             *remediationTemplateResponse  `json:"remediation-template,omitempty"`
}

type addEvidenceLinkRequest struct {
	EvidenceID uuid.UUID `json:"evidence-id"`
}

type addControlLinkRequest struct {
	CatalogID uuid.UUID `json:"catalog-id"`
	ControlID string    `json:"control-id"`
}

type addComponentLinkRequest struct {
	ComponentID uuid.UUID `json:"component-id"`
}

type addSubjectLinkRequest struct {
	SubjectID uuid.UUID `json:"subject-id"`
}

type acceptRiskRequest struct {
	Justification  string    `json:"justification"`
	ReviewDeadline time.Time `json:"review-deadline"`
}

type reviewRiskRequest struct {
	ReviewedAt         *time.Time `json:"reviewed-at"`
	Decision           string     `json:"decision"`
	Notes              *string    `json:"notes"`
	Likelihood         *string    `json:"likelihood"`
	Impact             *string    `json:"impact"`
	NextReviewDeadline *time.Time `json:"next-review-deadline"`
}

// List godoc
//
//	@Summary		List risks
//	@Description	Lists risk register entries with filtering, sorting, and pagination.
//	@Tags			Risks
//	@Produce		json
//	@Param			status					query		string	false	"Risk status"
//	@Param			likelihood				query		string	false	"Risk likelihood"
//	@Param			impact					query		string	false	"Risk impact"
//	@Param			sspId					query		string	false	"SSP ID"
//	@Param			controlId				query		string	false	"Control ID"
//	@Param			componentId				query		string	false	"Component ID"
//	@Param			evidenceId				query		string	false	"Evidence ID"
//	@Param			ownerKind				query		string	false	"Owner kind"
//	@Param			ownerRef				query		string	false	"Owner reference"
//	@Param			reviewDeadlineBefore	query		string	false	"Review deadline upper bound (RFC3339)"
//	@Param			page					query		int		false	"Page number"
//	@Param			limit					query		int		false	"Page size"
//	@Param			sort					query		string	false	"Sort field"
//	@Param			order					query		string	false	"Sort order (asc|desc)"
//	@Success		200						{object}	svc.ListResponse[riskResponse]
//	@Failure		400						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks [get]
func (h *RiskHandler) List(ctx echo.Context) error {
	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	filters, err := parseListFilters(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	items, total, err := h.riskService.List(riskrel.ListParams{
		Filters:   filters,
		SortField: ctx.QueryParam("sort"),
		SortOrder: ctx.QueryParam("order"),
		Limit:     pagination.Limit,
		Offset:    pagination.Offset,
	})
	if err != nil {
		return h.internalServerError(ctx, "failed to list risks", err)
	}

	resp := make([]riskResponse, 0, len(items))
	riskIDs := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		if item.ID == nil {
			return h.internalServerError(ctx, "risk is missing id", fmt.Errorf("risk is missing id"))
		}
		riskIDs = append(riskIDs, *item.ID)
	}

	associationsByRiskID, err := h.riskService.GetAssociationsByRiskIDs(riskIDs)
	if err != nil {
		return h.internalServerError(ctx, "failed to load risk associations", err)
	}

	for _, item := range items {
		associations := associationsByRiskID[*item.ID]
		resp = append(resp, h.mapRiskToResponseWithAssociations(&item, associations))
	}

	return ctx.JSON(http.StatusOK, svc.NewListResponse(resp, total, pagination.Page, pagination.Limit))
}

// Create godoc
//
//	@Summary		Create risk
//	@Description	Creates a risk register entry.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			risk	body		createRiskRequest	true	"Risk payload"
//	@Success		201		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks [post]
func (h *RiskHandler) Create(ctx echo.Context) error {
	var req createRiskRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return h.createFromRequest(ctx, req)
}

func (h *RiskHandler) createFromRequest(ctx echo.Context, req createRiskRequest) error {
	if req.Title == "" || req.Description == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("title and description are required")))
	}
	if err := validateTextLength("title", req.Title, maxRiskTitleLength); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := validateTextLength("description", req.Description, maxRiskDescriptionLength); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.SSPID == uuid.Nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("sspId is required")))
	}
	if err := h.riskService.EnsureSSPExists(req.SSPID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("ssp not found")))
		}
		return h.internalServerError(ctx, "failed to validate ssp", err)
	}
	if err := validateRiskLevel(req.Likelihood); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := validateRiskLevel(req.Impact); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	req.Likelihood = riskrel.NormalizeRiskLevelPtr(req.Likelihood)
	req.Impact = riskrel.NormalizeRiskLevelPtr(req.Impact)
	if err := validateOwnerAssignments(req.OwnerAssignments); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	status := string(riskrel.RiskStatusOpen)
	if req.Status != nil {
		status = *req.Status
	}
	if !riskrel.RiskStatus(status).IsValid() {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid status: %s", status)))
	}

	var reviewDeadline *time.Time
	if req.ReviewDeadline != nil {
		reviewDeadlineUTC := req.ReviewDeadline.UTC()
		reviewDeadline = &reviewDeadlineUTC
	}
	var lastReviewedAt *time.Time
	if req.LastReviewedAt != nil {
		lastReviewedAtUTC := req.LastReviewedAt.UTC()
		lastReviewedAt = &lastReviewedAtUTC
	}

	if err := validateAcceptedRequirements(status, reviewDeadline, req.AcceptanceJustification); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		now := time.Now().UTC()
		ownerAssignments := normalizeOwnerAssignmentsForPrimaryOwner(toOwnerAssignments(req.OwnerAssignments), req.PrimaryOwnerUserID)
		risk := riskrel.Risk{
			Title:                   req.Title,
			Description:             req.Description,
			Status:                  status,
			SSPID:                   req.SSPID,
			PrimaryOwnerUserID:      req.PrimaryOwnerUserID,
			Likelihood:              req.Likelihood,
			Impact:                  req.Impact,
			RiskTemplateID:          req.RiskTemplateID,
			SourceType:              string(riskrel.RiskSourceTypeManual),
			ReviewDeadline:          reviewDeadline,
			LastReviewedAt:          lastReviewedAt,
			AcceptanceJustification: req.AcceptanceJustification,
			FirstSeenAt:             now,
			LastSeenAt:              now,
		}
		created, err := h.riskService.Create(riskrel.CreateRiskParams{
			Risk:             risk,
			OwnerAssignments: ownerAssignments,
			ThreatRefs:       toThreatRefs(req.ThreatIDs),
			Remediation:      toRemediation(req.Remediation),
			ActorUserID:      actorID,
		})
		if err != nil {
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to create risk", err)
		}

		mapped, err := h.mapRiskToResponse(created)
		if err != nil {
			return h.internalServerError(ctx, "failed to map created risk", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[riskResponse]{Data: mapped})
	})
}

// ListForSSP godoc
//
//	@Summary		List risks for SSP
//	@Description	Lists risk register entries scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId					path		string	true	"SSP ID"
//	@Param			status					query		string	false	"Risk status"
//	@Param			likelihood				query		string	false	"Risk likelihood"
//	@Param			impact					query		string	false	"Risk impact"
//	@Param			controlId				query		string	false	"Control ID"
//	@Param			componentId				query		string	false	"Component ID"
//	@Param			evidenceId				query		string	false	"Evidence ID"
//	@Param			ownerKind				query		string	false	"Owner kind"
//	@Param			ownerRef				query		string	false	"Owner reference"
//	@Param			reviewDeadlineBefore	query		string	false	"Review deadline upper bound (RFC3339)"
//	@Param			page					query		int		false	"Page number"
//	@Param			limit					query		int		false	"Page size"
//	@Param			sort					query		string	false	"Sort field"
//	@Param			order					query		string	false	"Sort order (asc|desc)"
//	@Success		200						{object}	svc.ListResponse[riskResponse]
//	@Failure		400						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks [get]
func (h *RiskHandler) ListForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.riskService.EnsureSSPExists(sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("ssp not found")))
		}
		return h.internalServerError(ctx, "failed to validate ssp", err)
	}

	q := ctx.QueryParams()
	q.Set("sspId", sspID.String())
	ctx.Request().URL.RawQuery = q.Encode()
	return h.List(ctx)
}

// CreateForSSP godoc
//
//	@Summary		Create risk for SSP
//	@Description	Creates a risk register entry scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string				true	"SSP ID"
//	@Param			risk	body		createRiskRequest	true	"Risk payload"
//	@Success		201		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks [post]
func (h *RiskHandler) CreateForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req createRiskRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	req.SSPID = sspID
	return h.createFromRequest(ctx, req)
}

// GetForSSP godoc
//
//	@Summary		Get risk for SSP
//	@Description	Retrieves a risk register entry by ID scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Success		200		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id} [get]
func (h *RiskHandler) GetForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.Get(ctx)
}

// UpdateForSSP godoc
//
//	@Summary		Update risk for SSP
//	@Description	Updates a risk register entry by ID scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string				true	"SSP ID"
//	@Param			id		path		string				true	"Risk ID"
//	@Param			risk	body		updateRiskRequest	true	"Risk payload"
//	@Success		200		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id} [put]
func (h *RiskHandler) UpdateForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.Update(ctx)
}

// DeleteForSSP godoc
//
//	@Summary		Delete risk for SSP
//	@Description	Deletes a risk register entry by ID scoped to an SSP.
//	@Tags			Risks
//	@Param			sspId	path	string	true	"SSP ID"
//	@Param			id		path	string	true	"Risk ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id} [delete]
func (h *RiskHandler) DeleteForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.Delete(ctx)
}

// AcceptForSSP godoc
//
//	@Summary		Accept risk for SSP
//	@Description	Accepts a risk by ID scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string				true	"SSP ID"
//	@Param			id		path		string				true	"Risk ID"
//	@Param			body	body		acceptRiskRequest	true	"Accept payload"
//	@Success		200		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/accept [post]
func (h *RiskHandler) AcceptForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.Accept(ctx)
}

// ReviewForSSP godoc
//
//	@Summary		Review risk for SSP
//	@Description	Records a risk review by ID scoped to an SSP. For decision=extend, nextReviewDeadline is required and risk must be risk-accepted. For decision=reopen, nextReviewDeadline must be omitted and risk must be risk-accepted. For decision=reassess, likelihood and impact are required, nextReviewDeadline must be omitted, and risk must be open/investigating/mitigating-implemented.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string				true	"SSP ID"
//	@Param			id		path		string				true	"Risk ID"
//	@Param			body	body		reviewRiskRequest	true	"Review payload"
//	@Success		200		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/review [post]
func (h *RiskHandler) ReviewForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.Review(ctx)
}

func (h *RiskHandler) ensureRiskBelongsToSSP(riskID, sspID uuid.UUID) error {
	return h.riskService.EnsureRiskInSSP(riskID, sspID)
}

// Get godoc
//
//	@Summary		Get risk
//	@Description	Retrieves a risk register entry by ID.
//	@Tags			Risks
//	@Produce		json
//	@Param			id	path		string	true	"Risk ID"
//	@Success		200	{object}	GenericDataResponse[riskResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id} [get]
func (h *RiskHandler) Get(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	risk, err := h.riskService.GetByID(riskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalServerError(ctx, "failed to load risk", err)
	}

	mapped, err := h.mapRiskToResponse(risk)
	if err != nil {
		return h.internalServerError(ctx, "failed to map risk", err)
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[riskResponse]{Data: mapped})
}

// Update godoc
//
//	@Summary		Update risk
//	@Description	Updates a risk register entry by ID.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Risk ID"
//	@Param			risk	body		updateRiskRequest	true	"Risk payload"
//	@Success		200		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id} [put]
func (h *RiskHandler) Update(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	decoder := json.NewDecoder(ctx.Request().Body)
	rawFields := map[string]json.RawMessage{}
	if err := decoder.Decode(&rawFields); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid request body")))
	}

	var req updateRiskRequest
	normalizedBody, err := json.Marshal(rawFields)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := json.Unmarshal(normalizedBody, &req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	threatIDsRaw, hasThreatIDs := rawFields["threat-ids"]
	if hasThreatIDs && strings.TrimSpace(string(threatIDsRaw)) == "null" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("threat-ids must be an array")))
	}
	replaceThreatRefs := hasThreatIDs
	threatRefs := make([]riskrel.RiskThreatRefInput, 0)
	if hasThreatIDs {
		threatRefs = toThreatRefs(req.ThreatIDs)
	}

	remediationRaw, hasRemediation := rawFields["remediation-template"]
	replaceRemediation := hasRemediation
	var remediation *riskrel.RiskRemediationTemplateInput
	if hasRemediation && strings.TrimSpace(string(remediationRaw)) != "null" {
		remediation = toRemediation(req.Remediation)
	}

	if err := validateRiskLevel(req.Likelihood); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := validateRiskLevel(req.Impact); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	req.Likelihood = riskrel.NormalizeRiskLevelPtr(req.Likelihood)
	req.Impact = riskrel.NormalizeRiskLevelPtr(req.Impact)
	if req.OwnerAssignments != nil {
		if err := validateOwnerAssignments(*req.OwnerAssignments); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		risk, err := h.riskService.GetByID(riskID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to load risk for update", err)
		}

		oldStatus := risk.Status
		statusChanged := false

		if req.Status != nil {
			if !riskrel.RiskStatus(*req.Status).IsValid() {
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid status: %s", *req.Status)))
			}
			if oldStatus != *req.Status {
				if err := validateStatusTransition(oldStatus, *req.Status); err != nil {
					return ctx.JSON(http.StatusBadRequest, api.NewError(err))
				}
				statusChanged = true
				risk.Status = *req.Status
			}
		}
		if req.Title != nil {
			if err := validateTextLength("title", *req.Title, maxRiskTitleLength); err != nil {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			risk.Title = *req.Title
		}
		if req.Description != nil {
			if err := validateTextLength("description", *req.Description, maxRiskDescriptionLength); err != nil {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			risk.Description = *req.Description
		}
		if req.Likelihood != nil {
			risk.Likelihood = req.Likelihood
		}
		if req.Impact != nil {
			risk.Impact = req.Impact
		}
		if req.RiskTemplateID != nil {
			risk.RiskTemplateID = req.RiskTemplateID
		}
		if req.ReviewDeadline != nil {
			reviewDeadline := req.ReviewDeadline.UTC()
			risk.ReviewDeadline = &reviewDeadline
		}
		if req.LastReviewedAt != nil {
			lastReviewedAt := req.LastReviewedAt.UTC()
			risk.LastReviewedAt = &lastReviewedAt
		}
		if req.AcceptanceJustification != nil {
			risk.AcceptanceJustification = req.AcceptanceJustification
		}
		effectivePrimaryOwnerUserID := risk.PrimaryOwnerUserID
		if req.PrimaryOwnerUserID != nil {
			effectivePrimaryOwnerUserID = req.PrimaryOwnerUserID
			risk.PrimaryOwnerUserID = req.PrimaryOwnerUserID
		}

		if err := validateAcceptedRequirements(risk.Status, risk.ReviewDeadline, risk.AcceptanceJustification); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}

		replaceOwnerAssignments := req.OwnerAssignments != nil || req.PrimaryOwnerUserID != nil
		ownerAssignments := risk.OwnerAssignments
		if req.OwnerAssignments != nil {
			ownerAssignments = toOwnerAssignments(*req.OwnerAssignments)
		}
		ownerAssignments = normalizeOwnerAssignmentsForPrimaryOwner(ownerAssignments, effectivePrimaryOwnerUserID)

		recordReview := req.LastReviewedAt != nil || req.ReviewDeadline != nil || req.ReviewJustification != nil
		var reviewedAt *time.Time
		if req.LastReviewedAt != nil {
			reviewedAtUTC := req.LastReviewedAt.UTC()
			reviewedAt = &reviewedAtUTC
		}

		updated, err := h.riskService.Update(riskrel.UpdateRiskParams{
			Risk:                    risk,
			ReplaceOwnerAssignments: replaceOwnerAssignments,
			OwnerAssignments:        ownerAssignments,
			PrimaryOwnerUserID:      effectivePrimaryOwnerUserID,
			ActorUserID:             actorID,
			OldStatus:               oldStatus,
			StatusChanged:           statusChanged,
			RecordReview:            recordReview,
			ReviewedAt:              reviewedAt,
			ReviewJustification:     req.ReviewJustification,
			ReplaceThreatRefs:       replaceThreatRefs,
			ThreatRefs:              threatRefs,
			ReplaceRemediation:      replaceRemediation,
			Remediation:             remediation,
		})
		if err != nil {
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to update risk", err)
		}

		mapped, err := h.mapRiskToResponse(updated)
		if err != nil {
			return h.internalServerError(ctx, "failed to map updated risk", err)
		}
		return ctx.JSON(http.StatusOK, GenericDataResponse[riskResponse]{Data: mapped})
	})
}

// Accept godoc
//
//	@Summary		Accept risk
//	@Description	Accepts a risk with required justification and a future review deadline.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Risk ID"
//	@Param			body	body		acceptRiskRequest	true	"Accept payload"
//	@Success		200		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/accept [post]
func (h *RiskHandler) Accept(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req acceptRiskRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if strings.TrimSpace(req.Justification) == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("justification is required")))
	}
	if req.ReviewDeadline.IsZero() {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("reviewDeadline is required")))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		accepted, err := h.riskService.AcceptRisk(riskrel.AcceptRiskParams{
			RiskID:         riskID,
			ActorUserID:    actorID,
			Justification:  req.Justification,
			ReviewDeadline: req.ReviewDeadline,
		})
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
			}
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to accept risk", err)
		}

		mapped, err := h.mapRiskToResponse(accepted)
		if err != nil {
			return h.internalServerError(ctx, "failed to map accepted risk", err)
		}
		return ctx.JSON(http.StatusOK, GenericDataResponse[riskResponse]{Data: mapped})
	})
}

// Review godoc
//
//	@Summary		Review risk
//	@Description	Records a structured review. For decision=extend, nextReviewDeadline is required and risk must be risk-accepted. For decision=reopen, nextReviewDeadline must be omitted and risk must be risk-accepted. For decision=reassess, likelihood and impact are required, nextReviewDeadline must be omitted, and risk must be open/investigating/mitigating-implemented.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Risk ID"
//	@Param			body	body		reviewRiskRequest	true	"Review payload"
//	@Success		200		{object}	GenericDataResponse[riskResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/review [post]
func (h *RiskHandler) Review(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req reviewRiskRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if strings.TrimSpace(req.Decision) == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("decision is required")))
	}
	decision := riskrel.NormalizeRiskReviewDecision(req.Decision)
	if decision == riskrel.RiskReviewDecisionReassess {
		if err := validateRiskLevel(req.Likelihood); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		if err := validateRiskLevel(req.Impact); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		req.Likelihood = riskrel.NormalizeRiskLevelPtr(req.Likelihood)
		req.Impact = riskrel.NormalizeRiskLevelPtr(req.Impact)
	} else {
		req.Likelihood = nil
		req.Impact = nil
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		reviewed, err := h.riskService.ReviewRisk(riskrel.ReviewRiskParams{
			RiskID:             riskID,
			ActorUserID:        actorID,
			ReviewedAt:         req.ReviewedAt,
			Decision:           decision,
			Notes:              req.Notes,
			Likelihood:         req.Likelihood,
			Impact:             req.Impact,
			NextReviewDeadline: req.NextReviewDeadline,
		})
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
			}
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to review risk", err)
		}

		mapped, err := h.mapRiskToResponse(reviewed)
		if err != nil {
			return h.internalServerError(ctx, "failed to map reviewed risk", err)
		}
		return ctx.JSON(http.StatusOK, GenericDataResponse[riskResponse]{Data: mapped})
	})
}

// Delete godoc
//
//	@Summary		Delete risk
//	@Description	Deletes a risk register entry and link rows by ID.
//	@Tags			Risks
//	@Param			id	path	string	true	"Risk ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id} [delete]
func (h *RiskHandler) Delete(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.riskService.Delete(riskID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to delete risk", err)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetEventsForSSP godoc
//
//	@Summary		List risk events for SSP
//	@Description	Lists events for a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskEvent]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/events [get]
func (h *RiskHandler) GetEventsForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.GetEvents(ctx)
}

// GetEvents godoc
//
//	@Summary		List risk events
//	@Description	Lists events for a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskEvent]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/events [get]
func (h *RiskHandler) GetEvents(ctx echo.Context) error {
	return h.withRiskListContext(ctx, func(riskID uuid.UUID, pagination *svc.PaginationParams) error {
		events, total, err := h.riskService.ListEvents(riskID, pagination.Limit, pagination.Offset)
		if err != nil {
			return h.internalServerError(ctx, "failed to list risk events", err)
		}

		return ctx.JSON(http.StatusOK, svc.NewListResponse(events, total, pagination.Page, pagination.Limit))
	})
}

// GetReviewsForSSP godoc
//
//	@Summary		List risk audit trail for SSP
//	@Description	Lists risk reviews (audit trail) for a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskReview]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/reviews [get]
func (h *RiskHandler) GetReviewsForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.GetReviews(ctx)
}

// GetReviews godoc
//
//	@Summary		List risk audit trail
//	@Description	Lists risk reviews (audit trail) for a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskReview]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/reviews [get]
func (h *RiskHandler) GetReviews(ctx echo.Context) error {
	return h.withRiskListContext(ctx, func(riskID uuid.UUID, pagination *svc.PaginationParams) error {
		reviews, total, err := h.riskService.ListReviews(riskID, pagination.Limit, pagination.Offset)
		if err != nil {
			return h.internalServerError(ctx, "failed to list risk reviews", err)
		}

		return ctx.JSON(http.StatusOK, svc.NewListResponse(reviews, total, pagination.Page, pagination.Limit))
	})
}

// GetEvidenceLinksForSSP godoc
//
//	@Summary		List risk evidence links for SSP
//	@Description	Lists evidence IDs linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[uuid.UUID]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/evidence [get]
func (h *RiskHandler) GetEvidenceLinksForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.GetEvidenceLinks(ctx)
}

// GetEvidenceLinks godoc
//
//	@Summary		List risk evidence links
//	@Description	Lists evidence IDs linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[uuid.UUID]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/evidence [get]
func (h *RiskHandler) GetEvidenceLinks(ctx echo.Context) error {
	return h.withRiskListContext(ctx, func(riskID uuid.UUID, pagination *svc.PaginationParams) error {
		ids, total, err := h.riskService.ListEvidenceLinks(riskID, pagination.Limit, pagination.Offset)
		if err != nil {
			return h.internalServerError(ctx, "failed to list risk evidence links", err)
		}

		return ctx.JSON(http.StatusOK, svc.NewListResponse(ids, total, pagination.Page, pagination.Limit))
	})
}

// AddEvidenceLinkForSSP godoc
//
//	@Summary		Link evidence to risk for SSP
//	@Description	Idempotently links an evidence item to a risk scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string					true	"SSP ID"
//	@Param			id		path		string					true	"Risk ID"
//	@Param			link	body		addEvidenceLinkRequest	true	"Evidence link payload"
//	@Success		201		{object}	GenericDataResponse[risks.RiskEvidenceLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/evidence [post]
func (h *RiskHandler) AddEvidenceLinkForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.AddEvidenceLink(ctx)
}

// AddEvidenceLink godoc
//
//	@Summary		Link evidence to risk
//	@Description	Idempotently links an evidence item to a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Risk ID"
//	@Param			link	body		addEvidenceLinkRequest	true	"Evidence link payload"
//	@Success		201		{object}	GenericDataResponse[risks.RiskEvidenceLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/evidence [post]
func (h *RiskHandler) AddEvidenceLink(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req addEvidenceLinkRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.EvidenceID == uuid.Nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("evidenceId is required")))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		link, err := h.riskService.AddEvidenceLink(riskID, req.EvidenceID, actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to add risk evidence link", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[riskrel.RiskEvidenceLink]{Data: *link})
	})
}

// DeleteEvidenceLinkForSSP godoc
//
//	@Summary		Delete risk evidence link for SSP
//	@Description	Deletes the link between a risk and evidence item scoped to an SSP.
//	@Tags			Risks
//	@Param			sspId		path	string	true	"SSP ID"
//	@Param			id			path	string	true	"Risk ID"
//	@Param			evidenceId	path	string	true	"Evidence ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/evidence/{evidenceId} [delete]
func (h *RiskHandler) DeleteEvidenceLinkForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.DeleteEvidenceLink(ctx)
}

// DeleteEvidenceLink godoc
//
//	@Summary		Delete risk evidence link
//	@Description	Deletes the link between a risk and evidence item.
//	@Tags			Risks
//	@Param			id			path	string	true	"Risk ID"
//	@Param			evidenceId	path	string	true	"Evidence ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/evidence/{evidenceId} [delete]
func (h *RiskHandler) DeleteEvidenceLink(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	evidenceID, err := parsePathUUID(ctx, "evidenceId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		deleted, err := h.riskService.DeleteEvidenceLink(riskID, evidenceID, actorID)
		if err != nil {
			return h.internalServerError(ctx, "failed to delete risk evidence link", err)
		}
		if !deleted {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk evidence link not found")))
		}
		return ctx.NoContent(http.StatusNoContent)
	})
}

// GetControlLinksForSSP godoc
//
//	@Summary		List risk control links for SSP
//	@Description	Lists controls linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskControlLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/controls [get]
func (h *RiskHandler) GetControlLinksForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.GetControlLinks(ctx)
}

// GetControlLinks godoc
//
//	@Summary		List risk control links
//	@Description	Lists controls linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskControlLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/controls [get]
func (h *RiskHandler) GetControlLinks(ctx echo.Context) error {
	return h.withRiskListContext(ctx, func(riskID uuid.UUID, pagination *svc.PaginationParams) error {
		links, total, err := h.riskService.ListControlLinks(riskID, pagination.Limit, pagination.Offset)
		if err != nil {
			return h.internalServerError(ctx, "failed to list risk control links", err)
		}

		return ctx.JSON(http.StatusOK, svc.NewListResponse(links, total, pagination.Page, pagination.Limit))
	})
}

// AddControlLinkForSSP godoc
//
//	@Summary		Link control to risk for SSP
//	@Description	Idempotently links a control to a risk scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string					true	"SSP ID"
//	@Param			id		path		string					true	"Risk ID"
//	@Param			link	body		addControlLinkRequest	true	"Control link payload"
//	@Success		201		{object}	GenericDataResponse[risks.RiskControlLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/controls [post]
func (h *RiskHandler) AddControlLinkForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.AddControlLink(ctx)
}

// AddControlLink godoc
//
//	@Summary		Link control to risk
//	@Description	Idempotently links a control to a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Risk ID"
//	@Param			link	body		addControlLinkRequest	true	"Control link payload"
//	@Success		201		{object}	GenericDataResponse[risks.RiskControlLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/controls [post]
func (h *RiskHandler) AddControlLink(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req addControlLinkRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.CatalogID == uuid.Nil || req.ControlID == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("catalogId and controlId are required")))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		link, err := h.riskService.AddControlLink(riskID, req.CatalogID, req.ControlID, actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to add risk control link", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[riskrel.RiskControlLink]{Data: *link})
	})
}

// DeleteControlLinkForSSP godoc
//
//	@Summary		Delete risk control link for SSP
//	@Description	Deletes the link between a risk and control scoped to an SSP.
//	@Tags			Risks
//	@Param			sspId		path	string	true	"SSP ID"
//	@Param			id			path	string	true	"Risk ID"
//	@Param			catalogId	path	string	true	"Catalog ID"
//	@Param			controlId	path	string	true	"Control ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/controls/{catalogId}/{controlId} [delete]
func (h *RiskHandler) DeleteControlLinkForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.DeleteControlLink(ctx)
}

// DeleteControlLink godoc
//
//	@Summary		Delete risk control link
//	@Description	Deletes the link between a risk and control.
//	@Tags			Risks
//	@Param			id			path	string	true	"Risk ID"
//	@Param			catalogId	path	string	true	"Catalog ID"
//	@Param			controlId	path	string	true	"Control ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/controls/{catalogId}/{controlId} [delete]
func (h *RiskHandler) DeleteControlLink(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	catalogID, err := parsePathUUID(ctx, "catalogId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	controlID := ctx.Param("controlId")
	if controlID == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("controlId is required")))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		deleted, err := h.riskService.DeleteControlLink(riskID, catalogID, controlID, actorID)
		if err != nil {
			return h.internalServerError(ctx, "failed to delete risk control link", err)
		}
		if !deleted {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk control link not found")))
		}
		return ctx.NoContent(http.StatusNoContent)
	})
}

// GetComponentLinksForSSP godoc
//
//	@Summary		List risk component links for SSP
//	@Description	Lists components linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskComponentLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/components [get]
func (h *RiskHandler) GetComponentLinksForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.GetComponentLinks(ctx)
}

// GetComponentLinks godoc
//
//	@Summary		List risk component links
//	@Description	Lists components linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskComponentLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/components [get]
func (h *RiskHandler) GetComponentLinks(ctx echo.Context) error {
	return h.withRiskListContext(ctx, func(riskID uuid.UUID, pagination *svc.PaginationParams) error {
		links, total, err := h.riskService.ListComponentLinks(riskID, pagination.Limit, pagination.Offset)
		if err != nil {
			return h.internalServerError(ctx, "failed to list risk component links", err)
		}

		return ctx.JSON(http.StatusOK, svc.NewListResponse(links, total, pagination.Page, pagination.Limit))
	})
}

// AddComponentLinkForSSP godoc
//
//	@Summary		Link component to risk for SSP
//	@Description	Idempotently links a component to a risk scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string					true	"SSP ID"
//	@Param			id		path		string					true	"Risk ID"
//	@Param			link	body		addComponentLinkRequest	true	"Component link payload"
//	@Success		201		{object}	GenericDataResponse[risks.RiskComponentLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/components [post]
func (h *RiskHandler) AddComponentLinkForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.AddComponentLink(ctx)
}

// AddComponentLink godoc
//
//	@Summary		Link component to risk
//	@Description	Idempotently links a component to a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Risk ID"
//	@Param			link	body		addComponentLinkRequest	true	"Component link payload"
//	@Success		201		{object}	GenericDataResponse[risks.RiskComponentLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/components [post]
func (h *RiskHandler) AddComponentLink(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req addComponentLinkRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.ComponentID == uuid.Nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("componentId is required")))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		link, err := h.riskService.AddComponentLink(riskID, req.ComponentID, actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to add risk component link", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[riskrel.RiskComponentLink]{Data: *link})
	})
}

// DeleteComponentLinkForSSP godoc
//
//	@Summary		Delete risk component link for SSP
//	@Description	Deletes the link between a risk and component scoped to an SSP.
//	@Tags			Risks
//	@Param			sspId		path	string	true	"SSP ID"
//	@Param			id			path	string	true	"Risk ID"
//	@Param			componentId	path	string	true	"Component ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/components/{componentId} [delete]
func (h *RiskHandler) DeleteComponentLinkForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.DeleteComponentLink(ctx)
}

// DeleteComponentLink godoc
//
//	@Summary		Delete risk component link
//	@Description	Deletes the link between a risk and component.
//	@Tags			Risks
//	@Param			id			path	string	true	"Risk ID"
//	@Param			componentId	path	string	true	"Component ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/components/{componentId} [delete]
func (h *RiskHandler) DeleteComponentLink(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	componentID, err := parsePathUUID(ctx, "componentId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		deleted, err := h.riskService.DeleteComponentLink(riskID, componentID, actorID)
		if err != nil {
			return h.internalServerError(ctx, "failed to delete risk component link", err)
		}
		if !deleted {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk component link not found")))
		}
		return ctx.NoContent(http.StatusNoContent)
	})
}

// GetSubjectLinks godoc
//
//	@Summary		List risk subject links
//	@Description	Lists subjects linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[risks.RiskSubjectLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/subjects [get]
func (h *RiskHandler) GetSubjectLinks(ctx echo.Context) error {
	return h.withRiskListContext(ctx, func(riskID uuid.UUID, pagination *svc.PaginationParams) error {
		links, total, err := h.riskService.ListSubjectLinks(riskID, pagination.Limit, pagination.Offset)
		if err != nil {
			return h.internalServerError(ctx, "failed to list risk subject links", err)
		}

		return ctx.JSON(http.StatusOK, svc.NewListResponse(links, total, pagination.Page, pagination.Limit))
	})
}

// AddSubjectLink godoc
//
//	@Summary		Link subject to risk
//	@Description	Idempotently links a subject to a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Risk ID"
//	@Param			link	body		addSubjectLinkRequest	true	"Subject link payload"
//	@Success		201		{object}	GenericDataResponse[risks.RiskSubjectLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/subjects [post]
func (h *RiskHandler) AddSubjectLink(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req addSubjectLinkRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.SubjectID == uuid.Nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("subjectId is required")))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		link, err := h.riskService.AddSubjectLink(riskID, req.SubjectID, actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to add risk subject link", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[riskrel.RiskSubjectLink]{Data: *link})
	})
}

func parseListFilters(ctx echo.Context) (riskrel.ListFilters, error) {
	filters := riskrel.ListFilters{}
	if v := ctx.QueryParam("status"); v != "" {
		filters.Status = &v
	}
	if v := ctx.QueryParam("likelihood"); v != "" {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return filters, fmt.Errorf("invalid likelihood")
		}
		normalized := string(riskrel.NormalizeRiskLevel(trimmed))
		if normalized == "" {
			normalized = trimmed
		}
		filters.Likelihood = &normalized
	}
	if v := ctx.QueryParam("impact"); v != "" {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return filters, fmt.Errorf("invalid impact")
		}
		normalized := string(riskrel.NormalizeRiskLevel(trimmed))
		if normalized == "" {
			normalized = trimmed
		}
		filters.Impact = &normalized
	}
	if v := ctx.QueryParam("controlId"); v != "" {
		filters.ControlID = &v
	}
	if componentID := ctx.QueryParam("componentId"); componentID != "" {
		parsed, err := uuid.Parse(componentID)
		if err != nil {
			return filters, fmt.Errorf("invalid componentId")
		}
		filters.ComponentID = &parsed
	}
	if v := ctx.QueryParam("ownerKind"); v != "" {
		filters.OwnerKind = &v
	}
	if v := ctx.QueryParam("ownerRef"); v != "" {
		filters.OwnerRef = &v
	}
	if sspID := ctx.QueryParam("sspId"); sspID != "" {
		parsed, err := uuid.Parse(sspID)
		if err != nil {
			return filters, fmt.Errorf("invalid sspId")
		}
		filters.SSPID = &parsed
	}
	if evidenceID := ctx.QueryParam("evidenceId"); evidenceID != "" {
		parsed, err := uuid.Parse(evidenceID)
		if err != nil {
			return filters, fmt.Errorf("invalid evidenceId")
		}
		filters.EvidenceID = &parsed
	}
	if before := ctx.QueryParam("reviewDeadlineBefore"); before != "" {
		parsed, err := time.Parse(time.RFC3339, before)
		if err != nil {
			return filters, fmt.Errorf("invalid reviewDeadlineBefore")
		}
		filters.ReviewDeadlineBefore = &parsed
	}
	return filters, nil
}

func validateRiskLevel(level *string) error {
	if level == nil || *level == "" {
		return nil
	}
	if !riskrel.NormalizeRiskLevel(*level).IsValid() {
		return fmt.Errorf("invalid risk level: %s", *level)
	}
	return nil
}

func validateTextLength(field, value string, max int) error {
	if utf8.RuneCountInString(value) > max {
		return fmt.Errorf("%s must be at most %d characters", field, max)
	}
	return nil
}

func validateOwnerAssignments(assignments []riskOwnerAssignmentRequest) error {
	primaryCount := 0
	seen := map[string]struct{}{}
	for _, assignment := range assignments {
		if assignment.OwnerKind != "user" && assignment.OwnerKind != "group" && assignment.OwnerKind != "role" {
			return fmt.Errorf("invalid ownerKind: %s", assignment.OwnerKind)
		}
		if assignment.OwnerRef == "" {
			return fmt.Errorf("ownerRef is required")
		}
		if assignment.OwnerKind == "user" {
			if _, err := uuid.Parse(assignment.OwnerRef); err != nil {
				return fmt.Errorf("ownerRef must be a valid UUID when ownerKind is user")
			}
		}
		key := assignment.OwnerKind + ":" + assignment.OwnerRef
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate owner assignment: %s", key)
		}
		seen[key] = struct{}{}
		if assignment.IsPrimary {
			primaryCount++
		}
	}
	if primaryCount > 1 {
		return fmt.Errorf("only one primary owner assignment is allowed")
	}
	return nil
}

func validateStatusTransition(oldStatus, newStatus string) error {
	allowed := map[string]map[string]struct{}{
		string(riskrel.RiskStatusOpen): {
			string(riskrel.RiskStatusInvestigating): {},
			string(riskrel.RiskStatusClosed):        {},
		},
		string(riskrel.RiskStatusInvestigating): {
			string(riskrel.RiskStatusMitigatingPlanned): {},
			string(riskrel.RiskStatusRiskAccepted):      {},
		},
		string(riskrel.RiskStatusMitigatingPlanned): {
			string(riskrel.RiskStatusMitigatingImplemented): {},
			string(riskrel.RiskStatusInvestigating):         {}, // mitigation can fail; risk returns to investigation
		},
		string(riskrel.RiskStatusMitigatingImplemented): {
			string(riskrel.RiskStatusClosed):     {},
			string(riskrel.RiskStatusRemediated): {}, // evidence fully green → remediated before close
		},
		string(riskrel.RiskStatusRiskAccepted): {
			string(riskrel.RiskStatusClosed):        {},
			string(riskrel.RiskStatusInvestigating): {}, // re-open accepted risk for investigation
		},
		string(riskrel.RiskStatusRemediated): {
			string(riskrel.RiskStatusOpen):   {},
			string(riskrel.RiskStatusClosed): {},
		},
		string(riskrel.RiskStatusClosed): {},
	}

	if _, ok := allowed[oldStatus][newStatus]; !ok {
		return fmt.Errorf("invalid status transition: %s -> %s", oldStatus, newStatus)
	}
	return nil
}

func validateAcceptedRequirements(status string, reviewDeadline *time.Time, acceptanceJustification *string) error {
	if status != string(riskrel.RiskStatusRiskAccepted) {
		return nil
	}
	if reviewDeadline == nil {
		return fmt.Errorf("reviewDeadline is required when status is risk-accepted")
	}
	if reviewDeadline.UTC().Before(time.Now().UTC()) {
		return fmt.Errorf("reviewDeadline must be in the future when status is risk-accepted")
	}
	if acceptanceJustification == nil || strings.TrimSpace(*acceptanceJustification) == "" {
		return fmt.Errorf("acceptanceJustification is required when status is risk-accepted")
	}
	return nil
}

func parsePathUUID(ctx echo.Context, name string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(ctx.Param(name))
	if err != nil {
		return uuid.Nil, err
	}
	return parsed, nil
}

func (h *RiskHandler) withRiskListContext(ctx echo.Context, fn func(riskID uuid.UUID, pagination *svc.PaginationParams) error) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskExists(riskID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate risk", err)
	}

	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return fn(riskID, pagination)
}

func (h *RiskHandler) withActorUserID(ctx echo.Context, fn func(actorID *uuid.UUID) error) error {
	actorID, code, err := h.resolveActorUserID(ctx)
	if err != nil {
		return ctx.JSON(code, api.NewError(err))
	}
	return fn(actorID)
}

func (h *RiskHandler) resolveActorUserID(ctx echo.Context) (*uuid.UUID, int, error) {
	claims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || claims == nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("missing authentication claims")
	}

	actorID, err := h.riskService.ResolveUserIDByEmail(claims.Subject)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, fmt.Errorf("user not found")
		}
		return nil, http.StatusInternalServerError, fmt.Errorf("internal server error")
	}

	return actorID, http.StatusOK, nil
}

func (h *RiskHandler) internalServerError(ctx echo.Context, message string, err error) error {
	if h.sugar != nil {
		h.sugar.Errorw(message, "error", err)
	}
	return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("internal server error")))
}

func (h *RiskHandler) ensureRiskExists(riskID uuid.UUID) error {
	return h.riskService.EnsureRiskExists(riskID)
}

func toOwnerAssignments(req []riskOwnerAssignmentRequest) []riskrel.RiskOwnerAssignment {
	rows := make([]riskrel.RiskOwnerAssignment, 0, len(req))
	for _, item := range req {
		rows = append(rows, riskrel.RiskOwnerAssignment{OwnerKind: item.OwnerKind, OwnerRef: item.OwnerRef, IsPrimary: item.IsPrimary})
	}
	return rows
}

func normalizeOwnerAssignmentsForPrimaryOwner(assignments []riskrel.RiskOwnerAssignment, primaryOwnerUserID *uuid.UUID) []riskrel.RiskOwnerAssignment {
	if primaryOwnerUserID == nil {
		return assignments
	}

	primaryOwnerRef := primaryOwnerUserID.String()
	normalized := make([]riskrel.RiskOwnerAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment.OwnerKind == "user" && assignment.OwnerRef == primaryOwnerRef {
			continue
		}
		assignment.IsPrimary = false
		normalized = append(normalized, assignment)
	}

	return normalized
}

func toThreatRefs(req []threatIDRequest) []riskrel.RiskThreatRefInput {
	rows := make([]riskrel.RiskThreatRefInput, 0, len(req))
	for _, item := range req {
		rows = append(rows, riskrel.RiskThreatRefInput{
			System:     item.System,
			ExternalID: item.ID,
			Title:      item.Title,
			URL:        item.URL,
		})
	}
	return rows
}

func toRemediation(req *remediationTemplateRequest) *riskrel.RiskRemediationTemplateInput {
	if req == nil {
		return nil
	}
	input := &riskrel.RiskRemediationTemplateInput{
		Title:       req.Title,
		Description: req.Description,
		Tasks:       make([]riskrel.RiskRemediationTaskInput, 0, len(req.Tasks)),
	}
	for _, task := range req.Tasks {
		input.Tasks = append(input.Tasks, riskrel.RiskRemediationTaskInput{
			Title:      task.Title,
			OrderIndex: task.OrderIndex,
		})
	}
	return input
}

func (h *RiskHandler) mapRiskToResponse(risk *riskrel.Risk) (riskResponse, error) {
	associations, err := h.riskService.GetLinkAssociations(*risk.ID)
	if err != nil {
		return riskResponse{}, err
	}
	associations.ThreatRefs = append(associations.ThreatRefs, risk.ThreatRefs...)
	associations.Remediation = risk.Remediation

	return h.mapRiskToResponseWithAssociations(risk, associations), nil
}

func (h *RiskHandler) mapRiskToResponseWithAssociations(risk *riskrel.Risk, associations riskrel.Associations) riskResponse {
	response := riskResponse{
		ID:                      *risk.ID,
		CreatedAt:               risk.CreatedAt,
		UpdatedAt:               risk.UpdatedAt,
		Title:                   risk.Title,
		Description:             risk.Description,
		Status:                  risk.Status,
		PrimaryOwnerUserID:      risk.PrimaryOwnerUserID,
		Likelihood:              riskrel.NormalizeRiskLevelPtr(risk.Likelihood),
		Impact:                  riskrel.NormalizeRiskLevelPtr(risk.Impact),
		SSPID:                   risk.SSPID,
		SourceType:              risk.SourceType,
		RiskTemplateID:          risk.RiskTemplateID,
		DedupeKey:               risk.DedupeKey,
		ReviewDeadline:          risk.ReviewDeadline,
		LastReviewedAt:          risk.LastReviewedAt,
		AcceptanceJustification: risk.AcceptanceJustification,
		FirstSeenAt:             risk.FirstSeenAt,
		LastSeenAt:              risk.LastSeenAt,
		OwnerAssignments:        make([]riskOwnerAssignmentResponse, 0, len(risk.OwnerAssignments)),
		EvidenceIDs:             make([]uuid.UUID, 0),
		ControlLinks:            make([]riskControlLinkResponse, 0),
		ComponentIDs:            make([]uuid.UUID, 0),
		SubjectIDs:              make([]uuid.UUID, 0),
		ThreatIDs:               make([]threatIDResponse, 0),
	}

	owners := append([]riskrel.RiskOwnerAssignment{}, risk.OwnerAssignments...)
	sort.SliceStable(owners, func(i, j int) bool {
		if owners[i].IsPrimary != owners[j].IsPrimary {
			return owners[i].IsPrimary
		}
		if owners[i].OwnerKind != owners[j].OwnerKind {
			return owners[i].OwnerKind < owners[j].OwnerKind
		}
		return owners[i].OwnerRef < owners[j].OwnerRef
	})
	for _, owner := range owners {
		response.OwnerAssignments = append(response.OwnerAssignments, riskOwnerAssignmentResponse{OwnerKind: owner.OwnerKind, OwnerRef: owner.OwnerRef, IsPrimary: owner.IsPrimary})
	}

	response.EvidenceIDs = append(response.EvidenceIDs, associations.EvidenceIDs...)
	response.ComponentIDs = append(response.ComponentIDs, associations.ComponentIDs...)
	response.SubjectIDs = append(response.SubjectIDs, associations.SubjectIDs...)

	for _, link := range associations.ControlLinks {
		response.ControlLinks = append(response.ControlLinks, riskControlLinkResponse{CatalogID: link.CatalogID, ControlID: link.ControlID})
	}
	for _, ref := range associations.ThreatRefs {
		if ref.ID == nil {
			continue
		}
		response.ThreatIDs = append(response.ThreatIDs, threatIDResponse{
			ID:     *ref.ID,
			System: ref.System,
			RefID:  ref.ExternalID,
			Title:  ref.Title,
			URL:    ref.URL,
		})
	}
	if associations.Remediation != nil && associations.Remediation.ID != nil {
		remediation := remediationTemplateResponse{
			ID:          *associations.Remediation.ID,
			Title:       associations.Remediation.Title,
			Description: associations.Remediation.Description,
			Tasks:       make([]remediationTaskResponse, 0, len(associations.Remediation.Tasks)),
		}
		for _, task := range associations.Remediation.Tasks {
			if task.ID == nil {
				continue
			}
			remediation.Tasks = append(remediation.Tasks, remediationTaskResponse{
				ID:         *task.ID,
				Title:      task.Title,
				OrderIndex: task.OrderIndex,
			})
		}
		response.Remediation = &remediation
	}

	return response
}

// promoteToPoamRequest is the request body for POST /risks/:id/promote-to-poam.
type promoteToPoamRequest struct {
	// Title overrides the risk's title as the POAM item title.
	// If omitted, the risk's own title is used.
	Title *string `json:"title"`
	// Deadline maps to PoamItem.PlannedCompletionDate.
	Deadline *time.Time `json:"deadline"`
	// ResourceRequired is a free-text planning field describing effort or budget needed.
	ResourceRequired *string `json:"resourceRequired"`
	// PrimaryOwnerUserID optionally overrides the POAM item owner.
	// If omitted, the risk's own PrimaryOwnerUserID is inherited automatically.
	PrimaryOwnerUserID *uuid.UUID `json:"primaryOwnerUserId"`
	// Milestones are additional milestones to append after any copied from the
	// risk's RemediationTemplate.
	Milestones []createMilestoneRequest `json:"milestones"`
}

// PromoteToPoam godoc
//
//	@Summary		Promote risk to POAM item
//	@Description	Promotes an investigating risk to a POAM item and transitions the risk to mitigating-planned. The risk must be in investigating status (risk-accepted risks cannot be promoted — they have been formally accepted as tolerable). The POAM item is pre-populated from the risk's data and any RemediationTemplate tasks. The entire operation is transactional.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Risk ID"
//	@Param			body	body		promoteToPoamRequest	false	"Promotion payload"
//	@Success		201		{object}	GenericDataResponse[poamItemResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/promote-to-poam [post]
func (h *RiskHandler) PromoteToPoam(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req promoteToPoamRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Map request milestones to service params.
	// OrderIndex is passed as a pointer; nil means auto-assign from slice position.
	var milestones []poamsvc.CreateMilestoneParams
	for _, m := range req.Milestones {
		milestones = append(milestones, poamsvc.CreateMilestoneParams{
			Title:                 m.Title,
			Description:           m.Description,
			Status:                m.Status,
			PlannedCompletionDate: m.PlannedCompletionDate,
			ResponsibleParty:      m.ResponsibleParty,
			Remarks:               m.Remarks,
			OrderIndex:            m.OrderIndex,
		})
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		poamItem, err := h.riskService.PromoteToPoam(h.poamService, riskrel.PromoteToPoamParams{
			RiskID:             riskID,
			ActorUserID:        actorID,
			Title:              req.Title,
			Deadline:           req.Deadline,
			ResourceRequired:   req.ResourceRequired,
			PrimaryOwnerUserID: req.PrimaryOwnerUserID,
			ExtraMilestones:    milestones,
		})
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
			}
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to promote risk to POAM item", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[poamItemResponse]{Data: toPoamItemResponse(poamItem)})
	})
}

// PromoteToPoamForSSP godoc
//
//	@Summary		Promote risk to POAM item (SSP-scoped)
//	@Description	Promotes an investigating risk to a POAM item, scoped to a specific SSP. The risk must belong to the given SSP and be in investigating status. On success, the risk transitions to mitigating-planned.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string					true	"SSP ID"
//	@Param			id		path		string					true	"Risk ID"
//	@Param			body	body		promoteToPoamRequest	false	"Promotion payload"
//	@Success		201		{object}	GenericDataResponse[poamItemResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/promote-to-poam [post]
func (h *RiskHandler) PromoteToPoamForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.PromoteToPoam(ctx)
}
