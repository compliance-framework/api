package handler

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// PoamItemsHandler handles all HTTP operations for POAM items and their
// sub-resources. It delegates all persistence to PoamService and contains no
// direct database access.
type PoamItemsHandler struct {
	poamService *poamsvc.PoamService
	sugar       *zap.SugaredLogger
}

// NewPoamItemsHandler constructs a PoamItemsHandler backed by the given db.
func NewPoamItemsHandler(logger *zap.SugaredLogger, db *gorm.DB) *PoamItemsHandler {
	return &PoamItemsHandler{
		poamService: poamsvc.NewPoamService(db),
		sugar:       logger,
	}
}

// Register mounts all POAM item routes onto the given Echo group.
func (h *PoamItemsHandler) Register(g *echo.Group) {
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

type createMilestoneRequest struct {
	Title                   string     `json:"title"`
	Description             string     `json:"description"`
	Status                  string     `json:"status"`
	ScheduledCompletionDate *time.Time `json:"scheduledCompletionDate"`
	OrderIndex              int        `json:"orderIndex"`
}

type updateMilestoneRequest struct {
	Title                   *string    `json:"title"`
	Description             *string    `json:"description"`
	Status                  *string    `json:"status"`
	ScheduledCompletionDate *time.Time `json:"scheduledCompletionDate"`
	OrderIndex              *int       `json:"orderIndex"`
}

type poamControlRef struct {
	CatalogID string `json:"catalogId"`
	ControlID string `json:"controlId"`
}

type createPoamRequest struct {
	SspID                 string                   `json:"sspId"`
	Title                 string                   `json:"title"`
	Description           string                   `json:"description"`
	Status                string                   `json:"status"`
	PrimaryOwnerUserID    *string                  `json:"primaryOwnerUserId"`
	SourceType            string                   `json:"sourceType"`
	PlannedCompletionDate *time.Time               `json:"plannedCompletionDate"`
	CreatedFromRiskID     *string                  `json:"createdFromRiskId"`
	AcceptanceRationale   *string                  `json:"acceptanceRationale"`
	RiskIDs               []string                 `json:"riskIds"`
	EvidenceIDs           []string                 `json:"evidenceIds"`
	ControlRefs           []poamControlRef         `json:"controlRefs"`
	FindingIDs            []string                 `json:"findingIds"`
	Milestones            []createMilestoneRequest `json:"milestones"`
}

type updatePoamRequest struct {
	Title                 *string    `json:"title"`
	Description           *string    `json:"description"`
	Status                *string    `json:"status"`
	PrimaryOwnerUserID    *string    `json:"primaryOwnerUserId"`
	PlannedCompletionDate *time.Time `json:"plannedCompletionDate"`
	CompletedAt           *time.Time `json:"completedAt"`
	AcceptanceRationale   *string    `json:"acceptanceRationale"`
}

type addLinkRequest struct {
	ID string `json:"id"`
}

type poamAddControlLinkRequest struct {
	CatalogID string `json:"catalogId"`
	ControlID string `json:"controlId"`
}

// poamItemResponse is the typed API response for a POAM item. It avoids
// embedding the raw GORM model directly in the HTTP layer.
type poamItemResponse struct {
	ID                    uuid.UUID                      `json:"id"`
	CreatedAt             time.Time                      `json:"createdAt"`
	UpdatedAt             time.Time                      `json:"updatedAt"`
	SspID                 uuid.UUID                      `json:"sspId"`
	Title                 string                         `json:"title"`
	Description           string                         `json:"description"`
	Status                string                         `json:"status"`
	SourceType            string                         `json:"sourceType"`
	PrimaryOwnerUserID    *uuid.UUID                     `json:"primaryOwnerUserId,omitempty"`
	PlannedCompletionDate *time.Time                     `json:"plannedCompletionDate,omitempty"`
	CompletedAt           *time.Time                     `json:"completedAt,omitempty"`
	CreatedFromRiskID     *uuid.UUID                     `json:"createdFromRiskId,omitempty"`
	AcceptanceRationale   *string                        `json:"acceptanceRationale,omitempty"`
	LastStatusChangeAt    time.Time                      `json:"lastStatusChangeAt"`
	Milestones            []poamMilestoneResponse        `json:"milestones"`
	RiskLinks             []poamsvc.PoamItemRiskLink     `json:"riskLinks"`
	EvidenceLinks         []poamsvc.PoamItemEvidenceLink `json:"evidenceLinks"`
	ControlLinks          []poamsvc.PoamItemControlLink  `json:"controlLinks"`
	FindingLinks          []poamsvc.PoamItemFindingLink  `json:"findingLinks"`
}

// poamMilestoneResponse is the typed API response for a POAM milestone.
type poamMilestoneResponse struct {
	ID                      uuid.UUID  `json:"id"`
	CreatedAt               time.Time  `json:"createdAt"`
	UpdatedAt               time.Time  `json:"updatedAt"`
	PoamItemID              uuid.UUID  `json:"poamItemId"`
	Title                   string     `json:"title"`
	Description             string     `json:"description"`
	Status                  string     `json:"status"`
	ScheduledCompletionDate *time.Time `json:"scheduledCompletionDate,omitempty"`
	CompletionDate          *time.Time `json:"completionDate,omitempty"`
	OrderIndex              int        `json:"orderIndex"`
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

func mapPoamItemToResponse(item *poamsvc.PoamItem, riskLinks []poamsvc.PoamItemRiskLink, evidenceLinks []poamsvc.PoamItemEvidenceLink, controlLinks []poamsvc.PoamItemControlLink, findingLinks []poamsvc.PoamItemFindingLink) poamItemResponse {
	milestones := make([]poamMilestoneResponse, 0, len(item.Milestones))
	for _, m := range item.Milestones {
		milestones = append(milestones, mapMilestoneToResponse(&m))
	}
	if riskLinks == nil {
		riskLinks = []poamsvc.PoamItemRiskLink{}
	}
	if evidenceLinks == nil {
		evidenceLinks = []poamsvc.PoamItemEvidenceLink{}
	}
	if controlLinks == nil {
		controlLinks = []poamsvc.PoamItemControlLink{}
	}
	if findingLinks == nil {
		findingLinks = []poamsvc.PoamItemFindingLink{}
	}
	return poamItemResponse{
		ID:                    item.ID,
		CreatedAt:             item.CreatedAt,
		UpdatedAt:             item.UpdatedAt,
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
		LastStatusChangeAt:    item.LastStatusChangeAt,
		Milestones:            milestones,
		RiskLinks:             riskLinks,
		EvidenceLinks:         evidenceLinks,
		ControlLinks:          controlLinks,
		FindingLinks:          findingLinks,
	}
}

func mapMilestoneToResponse(m *poamsvc.PoamItemMilestone) poamMilestoneResponse {
	return poamMilestoneResponse{
		ID:                      m.ID,
		CreatedAt:               m.CreatedAt,
		UpdatedAt:               m.UpdatedAt,
		PoamItemID:              m.PoamItemID,
		Title:                   m.Title,
		Description:             m.Description,
		Status:                  m.Status,
		ScheduledCompletionDate: m.ScheduledCompletionDate,
		CompletionDate:          m.CompletionDate,
		OrderIndex:              m.OrderIndex,
	}
}

// ---------------------------------------------------------------------------
// POAM item handlers
// ---------------------------------------------------------------------------

// Create godoc
//
//	@Summary		Create a POAM item
//	@Description	Creates a POAM item with optional milestones and risk/evidence/control/finding links in a single transaction.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			body	body		createPoamRequest	true	"POAM item payload"
//	@Success		201		{object}	GenericDataResponse[poamItemResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items [post]
func (h *PoamItemsHandler) Create(c echo.Context) error {
	var in createPoamRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if in.Title == "" {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("title is required")))
	}
	sspID, err := uuid.Parse(in.SspID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("sspId must be a valid UUID")))
	}
	if err := h.poamService.EnsureSSPExists(sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("ssp not found")))
		}
		return h.internalError(c, "failed to validate ssp", err)
	}

	params := poamsvc.CreatePoamItemParams{
		SspID:                 sspID,
		Title:                 in.Title,
		Description:           in.Description,
		Status:                in.Status,
		SourceType:            in.SourceType,
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
	if in.CreatedFromRiskID != nil {
		riskID, err := uuid.Parse(*in.CreatedFromRiskID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("createdFromRiskId must be a valid UUID")))
		}
		params.CreatedFromRiskID = &riskID
	}

	for _, rid := range in.RiskIDs {
		ruuid, err := uuid.Parse(rid)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("riskIds contains invalid UUID: %s", rid)))
		}
		params.RiskIDs = append(params.RiskIDs, ruuid)
	}
	for _, eid := range in.EvidenceIDs {
		euuid, err := uuid.Parse(eid)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("evidenceIds contains invalid UUID: %s", eid)))
		}
		params.EvidenceIDs = append(params.EvidenceIDs, euuid)
	}
	for _, cr := range in.ControlRefs {
		catID, err := uuid.Parse(cr.CatalogID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("controlRefs contains invalid catalogId: %s", cr.CatalogID)))
		}
		params.ControlRefs = append(params.ControlRefs, poamsvc.ControlRef{CatalogID: catID, ControlID: cr.ControlID})
	}
	for _, fid := range in.FindingIDs {
		fuuid, err := uuid.Parse(fid)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("findingIds contains invalid UUID: %s", fid)))
		}
		params.FindingIDs = append(params.FindingIDs, fuuid)
	}
	for _, m := range in.Milestones {
		params.Milestones = append(params.Milestones, poamsvc.CreateMilestoneParams{
			Title:                   m.Title,
			Description:             m.Description,
			Status:                  m.Status,
			ScheduledCompletionDate: m.ScheduledCompletionDate,
			OrderIndex:              m.OrderIndex,
		})
	}

	item, err := h.poamService.Create(params)
	if err != nil {
		return h.internalError(c, "failed to create poam item", err)
	}

	riskLinks, _ := h.poamService.ListRiskLinks(item.ID)
	evidenceLinks, _ := h.poamService.ListEvidenceLinks(item.ID)
	controlLinks, _ := h.poamService.ListControlLinks(item.ID)
	findingLinks, _ := h.poamService.ListFindingLinks(item.ID)

	return c.JSON(http.StatusCreated, GenericDataResponse[poamItemResponse]{
		Data: mapPoamItemToResponse(item, riskLinks, evidenceLinks, controlLinks, findingLinks),
	})
}

// List godoc
//
//	@Summary		List POAM items
//	@Description	List POAM items with optional filters: status, sspId, riskId, dueBefore, overdueOnly, ownerRef.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			status		query		string	false	"open|in-progress|completed|overdue"
//	@Param			sspId		query		string	false	"SSP UUID"
//	@Param			riskId		query		string	false	"Risk UUID"
//	@Param			dueBefore	query		string	false	"RFC3339 timestamp — items with planned_completion_date before this value"
//	@Param			overdueOnly	query		bool	false	"true — items past planned_completion_date and not yet completed"
//	@Param			ownerRef	query		string	false	"UUID of primary_owner_user_id"
//	@Success		200			{object}	GenericDataListResponse[poamItemResponse]
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items [get]
func (h *PoamItemsHandler) List(c echo.Context) error {
	filters := poamsvc.ListFilters{}

	if v := c.QueryParam("status"); v != "" {
		filters.Status = &v
	}
	if v := c.QueryParam("sspId"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filters.SspID = &id
		}
	}
	if v := c.QueryParam("ownerRef"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filters.OwnerRef = &id
		}
	}
	if v := c.QueryParam("dueBefore"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filters.DueBefore = &t
		}
	}
	if c.QueryParam("overdueOnly") == "true" {
		filters.OverdueOnly = true
	}
	if v := c.QueryParam("riskId"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filters.RiskID = &id
		}
	}

	items, err := h.poamService.List(filters)
	if err != nil {
		return h.internalError(c, "failed to list poam items", err)
	}

	resp := make([]poamItemResponse, 0, len(items))
	for i := range items {
		resp = append(resp, mapPoamItemToResponse(&items[i], nil, nil, nil, nil))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[poamItemResponse]{Data: resp})
}

// Get godoc
//
//	@Summary		Get POAM item
//	@Description	Get a single POAM item with its milestones and all link sets.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataResponse[poamItemResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id} [get]
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

	riskLinks, _ := h.poamService.ListRiskLinks(id)
	evidenceLinks, _ := h.poamService.ListEvidenceLinks(id)
	controlLinks, _ := h.poamService.ListControlLinks(id)
	findingLinks, _ := h.poamService.ListFindingLinks(id)

	return c.JSON(http.StatusOK, GenericDataResponse[poamItemResponse]{
		Data: mapPoamItemToResponse(item, riskLinks, evidenceLinks, controlLinks, findingLinks),
	})
}

// Update godoc
//
//	@Summary		Update POAM item
//	@Description	Update scalar fields of a POAM item. Setting status to 'completed' automatically sets completed_at and last_status_change_at.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"POAM item ID"
//	@Param			body	body		updatePoamRequest	true	"Fields to update"
//	@Success		200		{object}	GenericDataResponse[poamItemResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id} [put]
func (h *PoamItemsHandler) Update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var in updatePoamRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	params := poamsvc.UpdatePoamItemParams{
		Title:                 in.Title,
		Description:           in.Description,
		Status:                in.Status,
		PlannedCompletionDate: in.PlannedCompletionDate,
		CompletedAt:           in.CompletedAt,
		AcceptanceRationale:   in.AcceptanceRationale,
	}
	if in.PrimaryOwnerUserID != nil {
		ownerID, err := uuid.Parse(*in.PrimaryOwnerUserID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("primaryOwnerUserId must be a valid UUID")))
		}
		params.PrimaryOwnerUserID = &ownerID
	}

	item, err := h.poamService.Update(id, params)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to update poam item", err)
	}

	riskLinks, _ := h.poamService.ListRiskLinks(id)
	evidenceLinks, _ := h.poamService.ListEvidenceLinks(id)
	controlLinks, _ := h.poamService.ListControlLinks(id)
	findingLinks, _ := h.poamService.ListFindingLinks(id)

	return c.JSON(http.StatusOK, GenericDataResponse[poamItemResponse]{
		Data: mapPoamItemToResponse(item, riskLinks, evidenceLinks, controlLinks, findingLinks),
	})
}

// Delete godoc
//
//	@Summary		Delete POAM item
//	@Description	Delete a POAM item and cascade-delete its milestones and all link records.
//	@Tags			POAM Items
//	@Param			id	path	string	true	"POAM item ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id} [delete]
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
//	@Summary		List milestones
//	@Description	List all milestones for a POAM item, ordered by order_index.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataListResponse[poamMilestoneResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/milestones [get]
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

	resp := make([]poamMilestoneResponse, 0, len(milestones))
	for i := range milestones {
		resp = append(resp, mapMilestoneToResponse(&milestones[i]))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[poamMilestoneResponse]{Data: resp})
}

// AddMilestone godoc
//
//	@Summary		Add milestone
//	@Description	Add a milestone to a POAM item.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"POAM item ID"
//	@Param			body	body		createMilestoneRequest	true	"Milestone payload"
//	@Success		201		{object}	GenericDataResponse[poamMilestoneResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/milestones [post]
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
	if in.Title == "" {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("title is required")))
	}

	m, err := h.poamService.AddMilestone(id, poamsvc.CreateMilestoneParams{
		Title:                   in.Title,
		Description:             in.Description,
		Status:                  in.Status,
		ScheduledCompletionDate: in.ScheduledCompletionDate,
		OrderIndex:              in.OrderIndex,
	})
	if err != nil {
		return h.internalError(c, "failed to add milestone", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[poamMilestoneResponse]{Data: mapMilestoneToResponse(m)})
}

// UpdateMilestone godoc
//
//	@Summary		Update milestone
//	@Description	Update milestone fields. When status becomes 'completed', completion_date is set automatically.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"POAM item ID"
//	@Param			milestoneId	path		string					true	"Milestone ID"
//	@Param			body		body		updateMilestoneRequest	true	"Fields to update"
//	@Success		200			{object}	GenericDataResponse[poamMilestoneResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/milestones/{milestoneId} [put]
func (h *PoamItemsHandler) UpdateMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	mid, err := uuid.Parse(c.Param("milestoneId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var in updateMilestoneRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	m, err := h.poamService.UpdateMilestone(id, mid, poamsvc.UpdateMilestoneParams{
		Title:                   in.Title,
		Description:             in.Description,
		Status:                  in.Status,
		ScheduledCompletionDate: in.ScheduledCompletionDate,
		OrderIndex:              in.OrderIndex,
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.internalError(c, "failed to update milestone", err)
	}
	return c.JSON(http.StatusOK, GenericDataResponse[poamMilestoneResponse]{Data: mapMilestoneToResponse(m)})
}

// DeleteMilestone godoc
//
//	@Summary		Delete milestone
//	@Tags			POAM Items
//	@Param			id			path	string	true	"POAM item ID"
//	@Param			milestoneId	path	string	true	"Milestone ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/milestones/{milestoneId} [delete]
func (h *PoamItemsHandler) DeleteMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	mid, err := uuid.Parse(c.Param("milestoneId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.poamService.DeleteMilestone(id, mid); err != nil {
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
//	@Summary		List linked risks
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataListResponse[poamsvc.PoamItemRiskLink]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/risks [get]
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
//	@Summary		Add risk link
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"POAM item ID"
//	@Param			body	body		addLinkRequest	true	"Risk ID payload"
//	@Success		201		{object}	GenericDataResponse[poamsvc.PoamItemRiskLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/risks [post]
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
//	@Summary		Delete risk link
//	@Tags			POAM Items
//	@Param			id		path	string	true	"POAM item ID"
//	@Param			riskId	path	string	true	"Risk ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/risks/{riskId} [delete]
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
//	@Summary		List linked evidence
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataListResponse[poamsvc.PoamItemEvidenceLink]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/evidence [get]
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
//	@Summary		Add evidence link
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"POAM item ID"
//	@Param			body	body		addLinkRequest	true	"Evidence ID payload"
//	@Success		201		{object}	GenericDataResponse[poamsvc.PoamItemEvidenceLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/evidence [post]
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
//	@Summary		Delete evidence link
//	@Tags			POAM Items
//	@Param			id			path	string	true	"POAM item ID"
//	@Param			evidenceId	path	string	true	"Evidence ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/evidence/{evidenceId} [delete]
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
//	@Summary		List linked controls
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataListResponse[poamsvc.PoamItemControlLink]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/controls [get]
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
//	@Summary		Add control link
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"POAM item ID"
//	@Param			body	body		addControlLinkRequest	true	"Control ref payload"
//	@Success		201		{object}	GenericDataResponse[poamsvc.PoamItemControlLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/controls [post]
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
	var in poamAddControlLinkRequest
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	catID, err := uuid.Parse(in.CatalogID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("catalogId must be a valid UUID")))
	}
	if in.ControlID == "" {
		return c.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("controlId is required")))
	}
	link, err := h.poamService.AddControlLink(id, poamsvc.ControlRef{CatalogID: catID, ControlID: in.ControlID})
	if err != nil {
		return h.internalError(c, "failed to add control link", err)
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[poamsvc.PoamItemControlLink]{Data: *link})
}

// DeleteControlLink godoc
//
//	@Summary		Delete control link
//	@Tags			POAM Items
//	@Param			id			path	string	true	"POAM item ID"
//	@Param			catalogId	path	string	true	"Catalog ID"
//	@Param			controlId	path	string	true	"Control ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/controls/{catalogId}/{controlId} [delete]
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
//	@Summary		List linked findings
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataListResponse[poamsvc.PoamItemFindingLink]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/findings [get]
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
//	@Summary		Add finding link
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"POAM item ID"
//	@Param			body	body		addLinkRequest	true	"Finding ID payload"
//	@Success		201		{object}	GenericDataResponse[poamsvc.PoamItemFindingLink]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/findings [post]
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
//	@Summary		Delete finding link
//	@Tags			POAM Items
//	@Param			id			path	string	true	"POAM item ID"
//	@Param			findingId	path	string	true	"Finding ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/poam-items/{id}/findings/{findingId} [delete]
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
// Error helper
// ---------------------------------------------------------------------------

func (h *PoamItemsHandler) internalError(c echo.Context, msg string, err error) error {
	h.sugar.Errorw(msg, "error", err)
	return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
