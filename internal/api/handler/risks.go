package handler

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	svc "github.com/compliance-framework/api/internal/service"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type RiskHandler struct {
	riskService *riskrel.RiskService
	sugar       *zap.SugaredLogger
	pagination  *svc.PaginationConfig
}

const (
	maxRiskTitleLength       = 1000
	maxRiskDescriptionLength = 1000
)

func NewRiskHandler(sugar *zap.SugaredLogger, db *gorm.DB) *RiskHandler {
	return &RiskHandler{
		riskService: riskrel.NewRiskService(db),
		sugar:       sugar,
		pagination:  svc.NewPaginationConfig(),
	}
}

func (h *RiskHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.POST("", h.Create)
	api.GET("/:id", h.Get)
	api.PUT("/:id", h.Update)
	api.DELETE("/:id", h.Delete)

	api.GET("/:id/evidence", h.GetEvidenceLinks)
	api.POST("/:id/evidence", h.AddEvidenceLink)
	api.DELETE("/:id/evidence/:evidenceId", h.DeleteEvidenceLink)

	api.GET("/:id/controls", h.GetControlLinks)
	api.POST("/:id/controls", h.AddControlLink)

	api.GET("/:id/components", h.GetComponentLinks)
	api.POST("/:id/components", h.AddComponentLink)

	api.GET("/:id/subjects", h.GetSubjectLinks)
	api.POST("/:id/subjects", h.AddSubjectLink)
}

func (h *RiskHandler) RegisterSSPScoped(api *echo.Group) {
	api.GET("", h.ListForSSP)
	api.POST("", h.CreateForSSP)
	api.GET("/:id", h.GetForSSP)
	api.PUT("/:id", h.UpdateForSSP)
	api.DELETE("/:id", h.DeleteForSSP)
}

type riskOwnerAssignmentRequest struct {
	OwnerKind string `json:"ownerKind"`
	OwnerRef  string `json:"ownerRef"`
	IsPrimary bool   `json:"isPrimary"`
}

type createRiskRequest struct {
	Title                   string                       `json:"title"`
	Description             string                       `json:"description"`
	Status                  *string                      `json:"status"`
	PrimaryOwnerUserID      *uuid.UUID                   `json:"primaryOwnerUserId"`
	OwnerAssignments        []riskOwnerAssignmentRequest `json:"ownerAssignments"`
	Likelihood              *string                      `json:"likelihood"`
	Impact                  *string                      `json:"impact"`
	SSPID                   uuid.UUID                    `json:"sspId"`
	RiskTemplateID          *uuid.UUID                   `json:"riskTemplateId"`
	ReviewDeadline          *time.Time                   `json:"reviewDeadline"`
	LastReviewedAt          *time.Time                   `json:"lastReviewedAt"`
	AcceptanceJustification *string                      `json:"acceptanceJustification"`
}

type updateRiskRequest struct {
	Title                   *string                       `json:"title"`
	Description             *string                       `json:"description"`
	Status                  *string                       `json:"status"`
	PrimaryOwnerUserID      *uuid.UUID                    `json:"primaryOwnerUserId"`
	OwnerAssignments        *[]riskOwnerAssignmentRequest `json:"ownerAssignments"`
	Likelihood              *string                       `json:"likelihood"`
	Impact                  *string                       `json:"impact"`
	RiskTemplateID          *uuid.UUID                    `json:"riskTemplateId"`
	ReviewDeadline          *time.Time                    `json:"reviewDeadline"`
	LastReviewedAt          *time.Time                    `json:"lastReviewedAt"`
	ReviewJustification     *string                       `json:"reviewJustification"`
	AcceptanceJustification *string                       `json:"acceptanceJustification"`
}

type riskOwnerAssignmentResponse struct {
	OwnerKind string `json:"ownerKind"`
	OwnerRef  string `json:"ownerRef"`
	IsPrimary bool   `json:"isPrimary"`
}

type riskControlLinkResponse struct {
	CatalogID uuid.UUID `json:"catalogId"`
	ControlID string    `json:"controlId"`
}

type riskResponse struct {
	ID                      uuid.UUID                     `json:"id"`
	CreatedAt               time.Time                     `json:"createdAt"`
	UpdatedAt               time.Time                     `json:"updatedAt"`
	Title                   string                        `json:"title"`
	Description             string                        `json:"description"`
	Status                  string                        `json:"status"`
	PrimaryOwnerUserID      *uuid.UUID                    `json:"primaryOwnerUserId"`
	OwnerAssignments        []riskOwnerAssignmentResponse `json:"ownerAssignments"`
	Likelihood              *string                       `json:"likelihood"`
	Impact                  *string                       `json:"impact"`
	SSPID                   uuid.UUID                     `json:"sspId"`
	SourceType              string                        `json:"sourceType"`
	RiskTemplateID          *uuid.UUID                    `json:"riskTemplateId"`
	DedupeKey               string                        `json:"dedupeKey"`
	ReviewDeadline          *time.Time                    `json:"reviewDeadline"`
	LastReviewedAt          *time.Time                    `json:"lastReviewedAt"`
	AcceptanceJustification *string                       `json:"acceptanceJustification"`
	FirstSeenAt             time.Time                     `json:"firstSeenAt"`
	LastSeenAt              time.Time                     `json:"lastSeenAt"`
	EvidenceIDs             []uuid.UUID                   `json:"evidenceIds"`
	ControlLinks            []riskControlLinkResponse     `json:"controlLinks"`
	ComponentIDs            []uuid.UUID                   `json:"componentIds"`
	SubjectIDs              []uuid.UUID                   `json:"subjectIds"`
}

type addEvidenceLinkRequest struct {
	EvidenceID uuid.UUID `json:"evidenceId"`
}

type addControlLinkRequest struct {
	CatalogID uuid.UUID `json:"catalogId"`
	ControlID string    `json:"controlId"`
}

type addComponentLinkRequest struct {
	ComponentID uuid.UUID `json:"componentId"`
}

type addSubjectLinkRequest struct {
	SubjectID uuid.UUID `json:"subjectId"`
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
			ActorUserID:      actorID,
		})
		if err != nil {
			return h.internalServerError(ctx, "failed to create risk", err)
		}

		mapped, err := h.mapRiskToResponse(created)
		if err != nil {
			return h.internalServerError(ctx, "failed to map created risk", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[riskResponse]{Data: mapped})
	})
}

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

	ctx.QueryParams().Set("sspId", sspID.String())
	return h.List(ctx)
}

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

func (h *RiskHandler) ensureRiskBelongsToSSP(riskID, sspID uuid.UUID) error {
	risk, err := h.riskService.GetByID(riskID)
	if err != nil {
		return err
	}
	if risk.SSPID != sspID {
		return gorm.ErrRecordNotFound
	}
	return nil
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

	var req updateRiskRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := validateRiskLevel(req.Likelihood); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := validateRiskLevel(req.Impact); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
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
		})
		if err != nil {
			return h.internalServerError(ctx, "failed to update risk", err)
		}

		mapped, err := h.mapRiskToResponse(updated)
		if err != nil {
			return h.internalServerError(ctx, "failed to map updated risk", err)
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
		filters.Likelihood = &v
	}
	if v := ctx.QueryParam("impact"); v != "" {
		filters.Impact = &v
	}
	if v := ctx.QueryParam("controlId"); v != "" {
		filters.ControlID = &v
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
	if !riskrel.RiskLevel(*level).IsValid() {
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
		},
		string(riskrel.RiskStatusInvestigating): {
			string(riskrel.RiskStatusMitigatingPlanned): {},
			string(riskrel.RiskStatusRiskAccepted):      {},
		},
		string(riskrel.RiskStatusMitigatingPlanned): {
			string(riskrel.RiskStatusMitigatingImplemented): {},
		},
		string(riskrel.RiskStatusMitigatingImplemented): {
			string(riskrel.RiskStatusClosed): {},
		},
		string(riskrel.RiskStatusRiskAccepted): {
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
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
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

func (h *RiskHandler) mapRiskToResponse(risk *riskrel.Risk) (riskResponse, error) {
	associations, err := h.riskService.GetAssociations(*risk.ID)
	if err != nil {
		return riskResponse{}, err
	}

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
		Likelihood:              risk.Likelihood,
		Impact:                  risk.Impact,
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

	return response
}
