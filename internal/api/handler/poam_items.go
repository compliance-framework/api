package handler

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// PoamItemsHandler handles all HTTP requests for POAM items and their
// sub-resources. It delegates all persistence to PoamService and never
// imports gorm directly for data access.
type PoamItemsHandler struct {
	poamService *poamsvc.PoamService
	riskService *riskrel.RiskService
	sugar       *zap.SugaredLogger
}

// NewPoamItemsHandler constructs a PoamItemsHandler.
func NewPoamItemsHandler(svc *poamsvc.PoamService, riskSvc *riskrel.RiskService, sugar *zap.SugaredLogger) *PoamItemsHandler {
	return &PoamItemsHandler{poamService: svc, riskService: riskSvc, sugar: sugar}
}

// Register mounts all POAM routes onto the given Echo group. JWT middleware
// is applied at the group level in api.go.
func (h *PoamItemsHandler) Register(g *echo.Group) {
	h.registerRoutes(g)
}

// RegisterSSPScoped mounts all POAM routes under an SSP-scoped group
// (e.g. /system-security-plans/:sspId/poam-items). The :sspId path param is
// extracted and injected into list/create filters automatically.
func (h *PoamItemsHandler) RegisterSSPScoped(g *echo.Group) {
	h.registerRoutes(g)
}

func (h *PoamItemsHandler) registerRoutes(g *echo.Group) {
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)

	g.GET("/:id/milestones", h.ListMilestones)
	g.POST("/:id/milestones", h.AddMilestone)
	g.PUT("/:id/milestones/:milestoneId", h.UpdateMilestone)
	g.DELETE("/:id/milestones/:milestoneId", h.DeleteMilestone)

	g.GET("/:id/risks", h.ListRisks)
	g.POST("/:id/risks", h.AddRiskLink)
	g.DELETE("/:id/risks/:riskId", h.DeleteRiskLink)

	g.GET("/:id/evidence", h.ListEvidence)
	g.POST("/:id/evidence", h.AddEvidenceLink)
	g.DELETE("/:id/evidence/:evidenceId", h.DeleteEvidenceLink)

	g.GET("/:id/controls", h.ListControls)
	g.POST("/:id/controls", h.AddControlLink)
	g.DELETE("/:id/controls/:catalogId/:controlId", h.DeleteControlLink)

	g.GET("/:id/findings", h.ListFindings)
	g.POST("/:id/findings", h.AddFindingLink)
	g.DELETE("/:id/findings/:findingId", h.DeleteFindingLink)
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

type createPoamItemRequest struct {
	SspID                 string                   `json:"sspId"                 validate:"required"`
	Title                 string                   `json:"title"                 validate:"required"`
	Description           string                   `json:"description"`
	Status                string                   `json:"status"`
	SourceType            string                   `json:"sourceType"`
	PrimaryOwnerUserID    *string                  `json:"primaryOwnerUserId"`
	PlannedCompletionDate *time.Time               `json:"plannedCompletionDate"`
	CreatedFromRiskID     *string                  `json:"createdFromRiskId"`
	AcceptanceRationale   *string                  `json:"acceptanceRationale"`
	PocName               *string                  `json:"pocName"`
	PocEmail              *string                  `json:"pocEmail"`
	ResourceRequired      *string                  `json:"resourceRequired"`
	RiskIDs               []string                 `json:"riskIds"`
	EvidenceIDs           []string                 `json:"evidenceIds"`
	ControlRefs           []poamControlRefRequest  `json:"controlRefs"`
	FindingIDs            []string                 `json:"findingIds"`
	Milestones            []createMilestoneRequest `json:"milestones"`
}

type updatePoamItemRequest struct {
	Title                 *string    `json:"title"`
	Description           *string    `json:"description"`
	Status                *string    `json:"status"`
	PrimaryOwnerUserID    *string    `json:"primaryOwnerUserId"`
	PlannedCompletionDate *time.Time `json:"plannedCompletionDate"`
	AcceptanceRationale   *string    `json:"acceptanceRationale"`
	// Link management — add/remove in the same call as scalar updates.
	AddRiskIDs        []string                `json:"addRiskIds"`
	RemoveRiskIDs     []string                `json:"removeRiskIds"`
	AddEvidenceIDs    []string                `json:"addEvidenceIds"`
	RemoveEvidenceIDs []string                `json:"removeEvidenceIds"`
	AddControlRefs    []poamControlRefRequest `json:"addControlRefs"`
	RemoveControlRefs []poamControlRefRequest `json:"removeControlRefs"`
	AddFindingIDs     []string                `json:"addFindingIds"`
	RemoveFindingIDs  []string                `json:"removeFindingIds"`
}

type createMilestoneRequest struct {
	Title                 string     `json:"title"    validate:"required"`
	Description           string     `json:"description"`
	Status                string     `json:"status"`
	PlannedCompletionDate *time.Time `json:"plannedCompletionDate"`
	ResponsibleParty      *string    `json:"responsibleParty"`
	Remarks               *string    `json:"remarks"`
	// OrderIndex is a pointer so that clients can explicitly set 0 without it
	// being indistinguishable from an omitted field.
	OrderIndex *int `json:"orderIndex"`
}

type updateMilestoneRequest struct {
	Title                 *string    `json:"title"`
	Description           *string    `json:"description"`
	Status                *string    `json:"status"`
	PlannedCompletionDate *time.Time `json:"plannedCompletionDate"`
	ResponsibleParty      *string    `json:"responsibleParty"`
	Remarks               *string    `json:"remarks"`
	OrderIndex            *int       `json:"orderIndex"`
}

type addLinkRequest struct {
	ID string `json:"id" validate:"required"`
}

type poamControlRefRequest struct {
	CatalogID string `json:"catalogId" validate:"required"`
	ControlID string `json:"controlId" validate:"required"`
}

// Response types — thin wrappers that avoid exposing raw GORM models.

type riskLinkResponse struct {
	PoamItemID uuid.UUID `json:"poamItemId"`
	RiskID     uuid.UUID `json:"riskId"`
	CreatedAt  time.Time `json:"createdAt"`
}

type evidenceLinkResponse struct {
	PoamItemID uuid.UUID `json:"poamItemId"`
	EvidenceID uuid.UUID `json:"evidenceId"`
	CreatedAt  time.Time `json:"createdAt"`
}

type controlLinkResponse struct {
	PoamItemID uuid.UUID `json:"poamItemId"`
	CatalogID  uuid.UUID `json:"catalogId"`
	ControlID  string    `json:"controlId"`
	CreatedAt  time.Time `json:"createdAt"`
}

type findingLinkResponse struct {
	PoamItemID uuid.UUID `json:"poamItemId"`
	FindingID  uuid.UUID `json:"findingId"`
	CreatedAt  time.Time `json:"createdAt"`
}

type poamItemResponse struct {
	ID                    uuid.UUID              `json:"id"`
	SspID                 uuid.UUID              `json:"sspId"`
	Title                 string                 `json:"title"`
	Description           string                 `json:"description"`
	Status                string                 `json:"status"`
	SourceType            string                 `json:"sourceType"`
	PrimaryOwnerUserID    *uuid.UUID             `json:"primaryOwnerUserId,omitempty"`
	PlannedCompletionDate *time.Time             `json:"plannedCompletionDate,omitempty"`
	CompletedAt           *time.Time             `json:"completedAt,omitempty"`
	CreatedFromRiskID     *uuid.UUID             `json:"createdFromRiskId,omitempty"`
	AcceptanceRationale   *string                `json:"acceptanceRationale,omitempty"`
	PocName               *string                `json:"pocName,omitempty"`
	PocEmail              *string                `json:"pocEmail,omitempty"`
	ResourceRequired      *string                `json:"resourceRequired,omitempty"`
	LastStatusChangeAt    time.Time              `json:"lastStatusChangeAt"`
	CreatedAt             time.Time              `json:"createdAt"`
	UpdatedAt             time.Time              `json:"updatedAt"`
	Milestones            []milestoneResponse    `json:"milestones,omitempty"`
	RiskLinks             []riskLinkResponse     `json:"riskLinks,omitempty"`
	EvidenceLinks         []evidenceLinkResponse `json:"evidenceLinks,omitempty"`
	ControlLinks          []controlLinkResponse  `json:"controlLinks,omitempty"`
	FindingLinks          []findingLinkResponse  `json:"findingLinks,omitempty"`
}

type milestoneResponse struct {
	ID                    uuid.UUID  `json:"id"`
	PoamItemID            uuid.UUID  `json:"poamItemId"`
	Title                 string     `json:"title"`
	Description           string     `json:"description"`
	Status                string     `json:"status"`
	PlannedCompletionDate *time.Time `json:"plannedCompletionDate,omitempty"`
	CompletionDate        *time.Time `json:"completionDate,omitempty"`
	ResponsibleParty      *string    `json:"responsibleParty,omitempty"`
	Remarks               *string    `json:"remarks,omitempty"`
	OrderIndex            int        `json:"orderIndex"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
}

func toPoamItemResponse(item *poamsvc.PoamItem) poamItemResponse {
	r := poamItemResponse{
		ID:                    item.ID,
		SspID:                 item.SspID,
		Title:                 item.Title,
		Description:           item.Description,
		Status:                item.Status,
		SourceType:            item.SourceType,
		PrimaryOwnerUserID:    item.PrimaryOwnerUserID,
		PlannedCompletionDate: item.PlannedCompletionDate,
		CompletedAt:           item.CompletedAt,
		CreatedFromRiskID:     item.CreatedFromRiskID,
		AcceptanceRationale:   item.AcceptanceRationale,
		PocName:               item.PocName,
		PocEmail:              item.PocEmail,
		ResourceRequired:      item.ResourceRequired,
		LastStatusChangeAt:    item.LastStatusChangeAt,
		CreatedAt:             item.CreatedAt,
		UpdatedAt:             item.UpdatedAt,
	}
	for _, m := range item.Milestones {
		r.Milestones = append(r.Milestones, toMilestoneResponse(&m))
	}
	for _, l := range item.RiskLinks {
		r.RiskLinks = append(r.RiskLinks, riskLinkResponse{
			PoamItemID: l.PoamItemID,
			RiskID:     l.RiskID,
			CreatedAt:  l.CreatedAt,
		})
	}
	for _, l := range item.EvidenceLinks {
		r.EvidenceLinks = append(r.EvidenceLinks, evidenceLinkResponse{
			PoamItemID: l.PoamItemID,
			EvidenceID: l.EvidenceID,
			CreatedAt:  l.CreatedAt,
		})
	}
	for _, l := range item.ControlLinks {
		r.ControlLinks = append(r.ControlLinks, controlLinkResponse{
			PoamItemID: l.PoamItemID,
			CatalogID:  l.CatalogID,
			ControlID:  l.ControlID,
			CreatedAt:  l.CreatedAt,
		})
	}
	for _, l := range item.FindingLinks {
		r.FindingLinks = append(r.FindingLinks, findingLinkResponse{
			PoamItemID: l.PoamItemID,
			FindingID:  l.FindingID,
			CreatedAt:  l.CreatedAt,
		})
	}
	return r
}

func toMilestoneResponse(m *poamsvc.PoamItemMilestone) milestoneResponse {
	return milestoneResponse{
		ID:                    m.ID,
		PoamItemID:            m.PoamItemID,
		Title:                 m.Title,
		Description:           m.Description,
		Status:                m.Status,
		PlannedCompletionDate: m.PlannedCompletionDate,
		CompletionDate:        m.CompletionDate,
		ResponsibleParty:      m.ResponsibleParty,
		Remarks:               m.Remarks,
		OrderIndex:            m.OrderIndex,
		CreatedAt:             m.CreatedAt,
		UpdatedAt:             m.UpdatedAt,
	}
}

// ---------------------------------------------------------------------------
// POAM item handlers
// ---------------------------------------------------------------------------

// List godoc
//
//	@Summary	List POAM items
//	@Tags		POAM Items
//	@Produce	json
//	@Param		status			query		string	false	"Filter by status (open|in-progress|completed|overdue)"
//	@Param		sspId			query		string	false	"Filter by SSP UUID"
//	@Param		riskId			query		string	false	"Filter by linked risk UUID"
//	@Param		deadlineBefore	query		string	false	"Filter by planned_completion_date before (RFC3339)"
//	@Param		overdueOnly		query		bool	false	"Return only overdue items"
//	@Param		ownerRef		query		string	false	"Filter by primary_owner_user_id UUID"
//	@Success	200				{object}	GenericDataListResponse[poamItemResponse]
//	@Failure	400				{object}	api.Error
//	@Failure	500				{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items [get]
func (h *PoamItemsHandler) List(c echo.Context) error {
	filters, err := parsePoamListFilters(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	// When mounted under /system-security-plans/:sspId/poam-items, the sspId
	// path param takes precedence over the query parameter.
	if sspIDParam := c.Param("sspId"); sspIDParam != "" {
		parsed, err := uuid.Parse(sspIDParam)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("sspId path param must be a valid UUID")))
		}
		filters.SspID = &parsed
	}
	items, err := h.poamService.List(filters)
	if err != nil {
		return h.internalError(c, "failed to list poam items", err)
	}
	resp := make([]poamItemResponse, 0, len(items))
	for i := range items {
		resp = append(resp, toPoamItemResponse(&items[i]))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[poamItemResponse]{Data: resp})
}

// Create godoc
//
//	@Summary	Create a POAM item
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		body	body		createPoamItemRequest	true	"POAM item payload"
//	@Success	201		{object}	GenericDataResponse[poamItemResponse]
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items [post]
func (h *PoamItemsHandler) Create(c echo.Context) error {
	var in createPoamItemRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	// When mounted under /system-security-plans/:sspId/poam-items, the sspId
	// path param overrides the body field so the client doesn't have to repeat it.
	if sspIDParam := c.Param("sspId"); sspIDParam != "" {
		in.SspID = sspIDParam
	}
	if err := c.Validate(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	sspID, err := uuid.Parse(in.SspID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("sspId must be a valid UUID")))
	}
	if err := h.poamService.EnsureSSPExists(sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("ssp not found: %s", sspID)))
		}
		return h.internalError(c, "failed to validate ssp", err)
	}

	if in.Status != "" && !poamsvc.PoamItemStatus(in.Status).IsValid() {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid status: %s", in.Status)))
	}
	if in.SourceType != "" && !poamsvc.PoamItemSourceType(in.SourceType).IsValid() {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid sourceType: %s", in.SourceType)))
	}

	params := poamsvc.CreatePoamItemParams{
		SspID:                 sspID,
		Title:                 in.Title,
		Description:           in.Description,
		Status:                in.Status,
		SourceType:            in.SourceType,
		PlannedCompletionDate: in.PlannedCompletionDate,
		AcceptanceRationale:   in.AcceptanceRationale,
		PocName:               in.PocName,
		PocEmail:              in.PocEmail,
		ResourceRequired:      in.ResourceRequired,
	}

	if in.PrimaryOwnerUserID != nil {
		ownerID, err := uuid.Parse(*in.PrimaryOwnerUserID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("primaryOwnerUserId must be a valid UUID")))
		}
		params.PrimaryOwnerUserID = &ownerID
	}
	if in.CreatedFromRiskID != nil {
		riskID, err := uuid.Parse(*in.CreatedFromRiskID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("createdFromRiskId must be a valid UUID")))
		}
		params.CreatedFromRiskID = &riskID
	}

	riskIDs, err := parseUUIDs(in.RiskIDs, "riskIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.RiskIDs = riskIDs

	evidenceIDs, err := parseUUIDs(in.EvidenceIDs, "evidenceIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.EvidenceIDs = evidenceIDs

	findingIDs, err := parseUUIDs(in.FindingIDs, "findingIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.FindingIDs = findingIDs

	controlRefs, err := parseControlRefs(in.ControlRefs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.ControlRefs = controlRefs

	for i, mr := range in.Milestones {
		if mr.Title == "" {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("milestone title is required")))
		}
		if mr.Status != "" && !poamsvc.MilestoneStatus(mr.Status).IsValid() {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid milestone status: %s", mr.Status)))
		}
		// When orderIndex is omitted (nil), fall back to the slice position so
		// ordering is still deterministic without requiring the client to set it.
		msOrderIdx := i
		if mr.OrderIndex != nil {
			msOrderIdx = *mr.OrderIndex
		}
		params.Milestones = append(params.Milestones, poamsvc.CreateMilestoneParams{
			Title:                 mr.Title,
			Description:           mr.Description,
			Status:                mr.Status,
			PlannedCompletionDate: mr.PlannedCompletionDate,
			ResponsibleParty:      mr.ResponsibleParty,
			Remarks:               mr.Remarks,
			OrderIndex:            msOrderIdx,
		})
	}

	item, err := h.poamService.Create(params)
	if err != nil {
		return h.internalError(c, "failed to create poam item", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[poamItemResponse]{Data: toPoamItemResponse(item)})
}

// Get godoc
//
//	@Summary	Get a POAM item
//	@Tags		POAM Items
//	@Produce	json
//	@Param		id	path		string	true	"POAM item ID"
//	@Success	200	{object}	GenericDataResponse[poamItemResponse]
//	@Failure	400	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id} [get]
func (h *PoamItemsHandler) Get(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	item, err := h.poamService.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to get poam item", err)
	}
	return c.JSON(http.StatusOK, GenericDataResponse[poamItemResponse]{Data: toPoamItemResponse(item)})
}

// Update godoc
//
//	@Summary	Update a POAM item
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		id		path		string					true	"POAM item ID"
//	@Param		body	body		updatePoamItemRequest	true	"Update payload"
//	@Success	200		{object}	GenericDataResponse[poamItemResponse]
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id} [put]
func (h *PoamItemsHandler) Update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var in updatePoamItemRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if in.Status != nil && !poamsvc.PoamItemStatus(*in.Status).IsValid() {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid status: %s", *in.Status)))
	}

	params := poamsvc.UpdatePoamItemParams{
		Title:                 in.Title,
		Description:           in.Description,
		Status:                in.Status,
		PlannedCompletionDate: in.PlannedCompletionDate,
		AcceptanceRationale:   in.AcceptanceRationale,
	}

	if in.PrimaryOwnerUserID != nil {
		ownerID, err := uuid.Parse(*in.PrimaryOwnerUserID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("primaryOwnerUserId must be a valid UUID")))
		}
		params.PrimaryOwnerUserID = &ownerID
	}

	addRiskIDs, err := parseUUIDs(in.AddRiskIDs, "addRiskIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.AddRiskIDs = addRiskIDs

	removeRiskIDs, err := parseUUIDs(in.RemoveRiskIDs, "removeRiskIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.RemoveRiskIDs = removeRiskIDs

	addEvidenceIDs, err := parseUUIDs(in.AddEvidenceIDs, "addEvidenceIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.AddEvidenceIDs = addEvidenceIDs

	removeEvidenceIDs, err := parseUUIDs(in.RemoveEvidenceIDs, "removeEvidenceIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.RemoveEvidenceIDs = removeEvidenceIDs

	addControlRefs, err := parseControlRefs(in.AddControlRefs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.AddControlRefs = addControlRefs

	removeControlRefs, err := parseControlRefs(in.RemoveControlRefs)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.RemoveControlRefs = removeControlRefs

	addFindingIDs, err := parseUUIDs(in.AddFindingIDs, "addFindingIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.AddFindingIDs = addFindingIDs

	removeFindingIDs, err := parseUUIDs(in.RemoveFindingIDs, "removeFindingIds")
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	params.RemoveFindingIDs = removeFindingIDs

	// Capture the current status before the update to detect a completion transition.
	currentItem, err := h.poamService.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to fetch poam item", err)
	}
	wasCompleted := currentItem.Status == string(poamsvc.PoamItemStatusCompleted)

	item, err := h.poamService.Update(id, params)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to update poam item", err)
	}

	// When a POAM item transitions to completed, advance all linked risks from
	// mitigating-planned → mitigating-implemented.
	nowCompleted := item.Status == string(poamsvc.PoamItemStatusCompleted)
	if !wasCompleted && nowCompleted {
		var actorUserID *uuid.UUID
		if claims, ok := c.Get("user").(*authn.UserClaims); ok && claims != nil {
			if uid, err := h.riskService.ResolveUserIDByEmail(claims.Subject); err == nil {
				actorUserID = uid
			}
		}
		if err := h.riskService.OnPoamItemCompleted(id, actorUserID); err != nil {
			// Log but do not fail the POAM update — the item is already saved.
			h.sugar.Warnw("failed to advance linked risk statuses on POAM completion",
				"poamItemId", id,
				"error", err,
			)
		}
	}

	return c.JSON(http.StatusOK, GenericDataResponse[poamItemResponse]{Data: toPoamItemResponse(item)})
}

// Delete godoc
//
//	@Summary	Delete a POAM item
//	@Tags		POAM Items
//	@Param		id	path	string	true	"POAM item ID"
//	@Success	204	"No Content"
//	@Failure	400	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id} [delete]
func (h *PoamItemsHandler) Delete(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.Delete(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to delete poam item", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Milestone handlers
// ---------------------------------------------------------------------------

// ListMilestones godoc
//
//	@Summary	List milestones for a POAM item
//	@Tags		POAM Items
//	@Produce	json
//	@Param		id	path		string	true	"POAM item ID"
//	@Success	200	{object}	GenericDataListResponse[milestoneResponse]
//	@Failure	400	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/milestones [get]
func (h *PoamItemsHandler) ListMilestones(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	milestones, err := h.poamService.ListMilestones(id)
	if err != nil {
		return h.internalError(c, "failed to list milestones", err)
	}
	resp := make([]milestoneResponse, 0, len(milestones))
	for i := range milestones {
		resp = append(resp, toMilestoneResponse(&milestones[i]))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[milestoneResponse]{Data: resp})
}

// AddMilestone godoc
//
//	@Summary	Add a milestone to a POAM item
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		id		path		string					true	"POAM item ID"
//	@Param		body	body		createMilestoneRequest	true	"Milestone payload"
//	@Success	201		{object}	GenericDataResponse[milestoneResponse]
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/milestones [post]
func (h *PoamItemsHandler) AddMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	var in createMilestoneRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := c.Validate(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if in.Status != "" && !poamsvc.MilestoneStatus(in.Status).IsValid() {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid milestone status: %s", in.Status)))
	}
	var orderIdx int
	if in.OrderIndex != nil {
		orderIdx = *in.OrderIndex
	}
	m, err := h.poamService.AddMilestone(id, poamsvc.CreateMilestoneParams{
		Title:                 in.Title,
		Description:           in.Description,
		Status:                in.Status,
		PlannedCompletionDate: in.PlannedCompletionDate,
		ResponsibleParty:      in.ResponsibleParty,
		Remarks:               in.Remarks,
		OrderIndex:            orderIdx,
	})
	if err != nil {
		return h.internalError(c, "failed to add milestone", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[milestoneResponse]{Data: toMilestoneResponse(m)})
}

// UpdateMilestone godoc
//
//	@Summary	Update a milestone
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		id			path		string					true	"POAM item ID"
//	@Param		milestoneId	path		string					true	"Milestone ID"
//	@Param		body		body		updateMilestoneRequest	true	"Milestone update payload"
//	@Success	200			{object}	GenericDataResponse[milestoneResponse]
//	@Failure	400			{object}	api.Error
//	@Failure	404			{object}	api.Error
//	@Failure	500			{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/milestones/{milestoneId} [put]
func (h *PoamItemsHandler) UpdateMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	milestoneID, err := uuid.Parse(c.Param("milestoneId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var in updateMilestoneRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if in.Status != nil && !poamsvc.MilestoneStatus(*in.Status).IsValid() {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid milestone status: %s", *in.Status)))
	}
	m, err := h.poamService.UpdateMilestone(id, milestoneID, poamsvc.UpdateMilestoneParams{
		Title:                 in.Title,
		Description:           in.Description,
		Status:                in.Status,
		PlannedCompletionDate: in.PlannedCompletionDate,
		ResponsibleParty:      in.ResponsibleParty,
		Remarks:               in.Remarks,
		OrderIndex:            in.OrderIndex,
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to update milestone", err)
	}
	return c.JSON(http.StatusOK, GenericDataResponse[milestoneResponse]{Data: toMilestoneResponse(m)})
}

// DeleteMilestone godoc
//
//	@Summary	Delete a milestone
//	@Tags		POAM Items
//	@Param		id			path	string	true	"POAM item ID"
//	@Param		milestoneId	path	string	true	"Milestone ID"
//	@Success	204			"No Content"
//	@Failure	400			{object}	api.Error
//	@Failure	404			{object}	api.Error
//	@Failure	500			{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/milestones/{milestoneId} [delete]
func (h *PoamItemsHandler) DeleteMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	milestoneID, err := uuid.Parse(c.Param("milestoneId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.DeleteMilestone(id, milestoneID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to delete milestone", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Risk link handlers
// ---------------------------------------------------------------------------

// ListRisks godoc
//
//	@Summary	List linked risks
//	@Tags		POAM Items
//	@Produce	json
//	@Param		id	path		string	true	"POAM item ID"
//	@Success	200	{object}	GenericDataListResponse[poamsvc.PoamItemRiskLink]
//	@Failure	400	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/risks [get]
func (h *PoamItemsHandler) ListRisks(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	links, err := h.poamService.ListRiskLinks(id)
	if err != nil {
		return h.internalError(c, "failed to list risk links", err)
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[poamsvc.PoamItemRiskLink]{Data: links})
}

// AddRiskLink godoc
//
//	@Summary	Add a risk link
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		id		path		string			true	"POAM item ID"
//	@Param		body	body		addLinkRequest	true	"Risk ID payload"
//	@Success	201		{object}	GenericDataResponse[poamsvc.PoamItemRiskLink]
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/risks [post]
func (h *PoamItemsHandler) AddRiskLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	var in addLinkRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := c.Validate(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := uuid.Parse(in.ID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("id must be a valid UUID")))
	}
	link, err := h.poamService.AddRiskLink(id, riskID)
	if err != nil {
		return h.internalError(c, "failed to add risk link", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[poamsvc.PoamItemRiskLink]{Data: *link})
}

// DeleteRiskLink godoc
//
//	@Summary	Delete a risk link
//	@Tags		POAM Items
//	@Param		id		path	string	true	"POAM item ID"
//	@Param		riskId	path	string	true	"Risk ID"
//	@Success	204		"No Content"
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/risks/{riskId} [delete]
func (h *PoamItemsHandler) DeleteRiskLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := uuid.Parse(c.Param("riskId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.DeleteRiskLink(id, riskID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to delete risk link", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Evidence link handlers
// ---------------------------------------------------------------------------

// ListEvidence godoc
//
//	@Summary	List linked evidence
//	@Tags		POAM Items
//	@Produce	json
//	@Param		id	path		string	true	"POAM item ID"
//	@Success	200	{object}	GenericDataListResponse[poamsvc.PoamItemEvidenceLink]
//	@Failure	400	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/evidence [get]
func (h *PoamItemsHandler) ListEvidence(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	links, err := h.poamService.ListEvidenceLinks(id)
	if err != nil {
		return h.internalError(c, "failed to list evidence links", err)
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[poamsvc.PoamItemEvidenceLink]{Data: links})
}

// AddEvidenceLink godoc
//
//	@Summary	Add an evidence link
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		id		path		string			true	"POAM item ID"
//	@Param		body	body		addLinkRequest	true	"Evidence ID payload"
//	@Success	201		{object}	GenericDataResponse[poamsvc.PoamItemEvidenceLink]
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/evidence [post]
func (h *PoamItemsHandler) AddEvidenceLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	var in addLinkRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := c.Validate(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	evidenceID, err := uuid.Parse(in.ID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("id must be a valid UUID")))
	}
	link, err := h.poamService.AddEvidenceLink(id, evidenceID)
	if err != nil {
		return h.internalError(c, "failed to add evidence link", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[poamsvc.PoamItemEvidenceLink]{Data: *link})
}

// DeleteEvidenceLink godoc
//
//	@Summary	Delete an evidence link
//	@Tags		POAM Items
//	@Param		id			path	string	true	"POAM item ID"
//	@Param		evidenceId	path	string	true	"Evidence ID"
//	@Success	204			"No Content"
//	@Failure	400			{object}	api.Error
//	@Failure	404			{object}	api.Error
//	@Failure	500			{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/evidence/{evidenceId} [delete]
func (h *PoamItemsHandler) DeleteEvidenceLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	evidenceID, err := uuid.Parse(c.Param("evidenceId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.DeleteEvidenceLink(id, evidenceID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to delete evidence link", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Control link handlers
// ---------------------------------------------------------------------------

// ListControls godoc
//
//	@Summary	List linked controls
//	@Tags		POAM Items
//	@Produce	json
//	@Param		id	path		string	true	"POAM item ID"
//	@Success	200	{object}	GenericDataListResponse[poamsvc.PoamItemControlLink]
//	@Failure	400	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/controls [get]
func (h *PoamItemsHandler) ListControls(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	links, err := h.poamService.ListControlLinks(id)
	if err != nil {
		return h.internalError(c, "failed to list control links", err)
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[poamsvc.PoamItemControlLink]{Data: links})
}

// AddControlLink godoc
//
//	@Summary	Add a control link
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		id		path		string					true	"POAM item ID"
//	@Param		body	body		poamControlRefRequest	true	"Control ref payload"
//	@Success	201		{object}	GenericDataResponse[poamsvc.PoamItemControlLink]
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/controls [post]
func (h *PoamItemsHandler) AddControlLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	var in poamControlRefRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := c.Validate(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	catID, err := uuid.Parse(in.CatalogID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("catalogId must be a valid UUID")))
	}
	link, err := h.poamService.AddControlLink(id, poamsvc.ControlRef{CatalogID: catID, ControlID: in.ControlID})
	if err != nil {
		return h.internalError(c, "failed to add control link", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[poamsvc.PoamItemControlLink]{Data: *link})
}

// DeleteControlLink godoc
//
//	@Summary	Delete a control link
//	@Tags		POAM Items
//	@Param		id			path	string	true	"POAM item ID"
//	@Param		catalogId	path	string	true	"Catalog ID"
//	@Param		controlId	path	string	true	"Control ID"
//	@Success	204			"No Content"
//	@Failure	400			{object}	api.Error
//	@Failure	404			{object}	api.Error
//	@Failure	500			{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/controls/{catalogId}/{controlId} [delete]
func (h *PoamItemsHandler) DeleteControlLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	catID, err := uuid.Parse(c.Param("catalogId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	controlID := c.Param("controlId")
	if controlID == "" {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("controlId path param is required")))
	}
	if err := h.poamService.DeleteControlLink(id, catID, controlID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to delete control link", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Finding link handlers
// ---------------------------------------------------------------------------

// ListFindings godoc
//
//	@Summary	List linked findings
//	@Tags		POAM Items
//	@Produce	json
//	@Param		id	path		string	true	"POAM item ID"
//	@Success	200	{object}	GenericDataListResponse[poamsvc.PoamItemFindingLink]
//	@Failure	400	{object}	api.Error
//	@Failure	404	{object}	api.Error
//	@Failure	500	{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/findings [get]
func (h *PoamItemsHandler) ListFindings(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	links, err := h.poamService.ListFindingLinks(id)
	if err != nil {
		return h.internalError(c, "failed to list finding links", err)
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[poamsvc.PoamItemFindingLink]{Data: links})
}

// AddFindingLink godoc
//
//	@Summary	Add a finding link
//	@Tags		POAM Items
//	@Accept		json
//	@Produce	json
//	@Param		id		path		string			true	"POAM item ID"
//	@Param		body	body		addLinkRequest	true	"Finding ID payload"
//	@Success	201		{object}	GenericDataResponse[poamsvc.PoamItemFindingLink]
//	@Failure	400		{object}	api.Error
//	@Failure	404		{object}	api.Error
//	@Failure	500		{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/findings [post]
func (h *PoamItemsHandler) AddFindingLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.EnsureExists(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to validate poam item", err)
	}
	var in addLinkRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := c.Validate(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	findingID, err := uuid.Parse(in.ID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("id must be a valid UUID")))
	}
	link, err := h.poamService.AddFindingLink(id, findingID)
	if err != nil {
		return h.internalError(c, "failed to add finding link", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[poamsvc.PoamItemFindingLink]{Data: *link})
}

// DeleteFindingLink godoc
//
//	@Summary	Delete a finding link
//	@Tags		POAM Items
//	@Param		id			path	string	true	"POAM item ID"
//	@Param		findingId	path	string	true	"Finding ID"
//	@Success	204			"No Content"
//	@Failure	400			{object}	api.Error
//	@Failure	404			{object}	api.Error
//	@Failure	500			{object}	api.Error
//	@Security	OAuth2Password
//	@Router		/poam-items/{id}/findings/{findingId} [delete]
func (h *PoamItemsHandler) DeleteFindingLink(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	findingID, err := uuid.Parse(c.Param("findingId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.poamService.DeleteFindingLink(id, findingID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to delete finding link", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseListFilters parses and validates all query parameters for the List
// endpoint. Returns 400-compatible errors for any malformed UUID or RFC3339
// value rather than silently ignoring them (Copilot item 12).
func parsePoamListFilters(c echo.Context) (poamsvc.ListFilters, error) {
	var f poamsvc.ListFilters

	if s := c.QueryParam("status"); s != "" {
		if !poamsvc.PoamItemStatus(s).IsValid() {
			return f, fmt.Errorf("invalid status filter: %s", s)
		}
		f.Status = s
	}

	if s := c.QueryParam("sspId"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			return f, fmt.Errorf("sspId must be a valid UUID")
		}
		f.SspID = &id
	}

	if s := c.QueryParam("riskId"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			return f, fmt.Errorf("riskId must be a valid UUID")
		}
		f.RiskID = &id
	}

	if s := c.QueryParam("deadlineBefore"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return f, fmt.Errorf("deadlineBefore must be an RFC3339 timestamp")
		}
		f.DeadlineBefore = &t
	}

	if s := c.QueryParam("overdueOnly"); s == "true" {
		f.OverdueOnly = true
	}

	if s := c.QueryParam("ownerRef"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			return f, fmt.Errorf("ownerRef must be a valid UUID")
		}
		f.OwnerRef = &id
	}

	return f, nil
}

// parseUUIDs converts a slice of raw strings to uuid.UUIDs, returning a
// descriptive 400 error for any malformed entry.
func parseUUIDs(raw []string, field string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid UUID: %s", field, s)
		}
		result = append(result, id)
	}
	return result, nil
}

// parseControlRefs converts a slice of poamControlRefRequest to ControlRef,
// validating the catalogId UUID in each entry.
func parseControlRefs(raw []poamControlRefRequest) ([]poamsvc.ControlRef, error) {
	result := make([]poamsvc.ControlRef, 0, len(raw))
	for _, r := range raw {
		catID, err := uuid.Parse(r.CatalogID)
		if err != nil {
			return nil, fmt.Errorf("controlRefs contains invalid catalogId UUID: %s", r.CatalogID)
		}
		if r.ControlID == "" {
			return nil, fmt.Errorf("controlRefs entry is missing controlId")
		}
		result = append(result, poamsvc.ControlRef{CatalogID: catID, ControlID: r.ControlID})
	}
	return result, nil
}

func (h *PoamItemsHandler) internalError(c echo.Context, msg string, err error) error {
	h.sugar.Errorw(msg, "error", err)
	return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
