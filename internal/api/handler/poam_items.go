package handler

import (
"net/http"
"time"

"github.com/compliance-framework/api/internal/api"
"github.com/compliance-framework/api/internal/service/relational"
"github.com/google/uuid"
"github.com/labstack/echo/v4"
"go.uber.org/zap"
"gorm.io/gorm"
)

type PoamItemsHandler struct {
db    *gorm.DB
sugar *zap.SugaredLogger
}

func NewPoamItemsHandler(logger *zap.SugaredLogger, db *gorm.DB) *PoamItemsHandler {
return &PoamItemsHandler{db: db, sugar: logger}
}

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
g.GET("/:id/evidence", h.ListEvidence)
g.GET("/:id/controls", h.ListControls)
g.GET("/:id/findings", h.ListFindings)
}

type createMilestoneRequest struct {
Title                   string     `json:"title"`
Description             string     `json:"description"`
Status                  string     `json:"status"`
ScheduledCompletionDate *time.Time `json:"scheduledCompletionDate"`
OrderIndex              int        `json:"orderIndex"`
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

type updateMilestoneRequest struct {
Title                   *string    `json:"title"`
Description             *string    `json:"description"`
Status                  *string    `json:"status"`
ScheduledCompletionDate *time.Time `json:"scheduledCompletionDate"`
OrderIndex              *int       `json:"orderIndex"`
}

type PoamItemResponse struct {
relational.CcfPoamItem
RiskLinks     []relational.CcfPoamItemRiskLink     `json:"riskLinks"`
EvidenceLinks []relational.CcfPoamItemEvidenceLink `json:"evidenceLinks"`
ControlLinks  []relational.CcfPoamItemControlLink  `json:"controlLinks"`
FindingLinks  []relational.CcfPoamItemFindingLink  `json:"findingLinks"`
}

func (h *PoamItemsHandler) itemExists(id uuid.UUID) (bool, error) {
var count int64
err := h.db.Model(&relational.CcfPoamItem{}).Where("id = ?", id).Count(&count).Error
return count > 0, err
}

// Create godoc
//
//@SummaryCreate a POAM item
//@DescriptionCreates a POAM item with optional milestones and risk/evidence/control/finding links in a single transaction.
//@TagsPOAM Items
//@Acceptjson
//@Producejson
//@ParambodybodycreatePoamRequesttrue"POAM item payload"
//@Success201{object}GenericDataResponse[relational.CcfPoamItem]
//@Failure400{object}api.Error
//@Failure500{object}api.Error
//@Router/poam-items [post]
func (h *PoamItemsHandler) Create(c echo.Context) error {
var in createPoamRequest
if err := c.Bind(&in); err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
sspID, err := uuid.Parse(in.SspID)
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
sourceType := in.SourceType
if sourceType == "" {
sourceType = "manual"
}
item := relational.CcfPoamItem{
ID:                    uuid.New(),
SspID:                 sspID,
Title:                 in.Title,
Description:           in.Description,
Status:                in.Status,
SourceType:            sourceType,
PlannedCompletionDate: in.PlannedCompletionDate,
AcceptanceRationale:   in.AcceptanceRationale,
LastStatusChangeAt:    time.Now().UTC(),
}
if in.PrimaryOwnerUserID != nil {
ownerID, err := uuid.Parse(*in.PrimaryOwnerUserID)
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
item.PrimaryOwnerUserID = &ownerID
}
if in.CreatedFromRiskID != nil {
riskID, err := uuid.Parse(*in.CreatedFromRiskID)
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
item.CreatedFromRiskID = &riskID
}
err = h.db.Transaction(func(tx *gorm.DB) error {
if err := tx.Create(&item).Error; err != nil {
return err
}
for i, m := range in.Milestones {
orderIdx := m.OrderIndex
if orderIdx == 0 {
orderIdx = i
}
ms := relational.CcfPoamItemMilestone{
ID:                      uuid.New(),
PoamItemID:              item.ID,
Title:                   m.Title,
Description:             m.Description,
Status:                  m.Status,
ScheduledCompletionDate: m.ScheduledCompletionDate,
OrderIndex:              orderIdx,
}
if err := tx.Create(&ms).Error; err != nil {
return err
}
}
for _, rid := range in.RiskIDs {
ruuid, err := uuid.Parse(rid)
if err != nil {
return err
}
if err := tx.Create(&relational.CcfPoamItemRiskLink{PoamItemID: item.ID, RiskID: ruuid}).Error; err != nil {
return err
}
}
for _, eid := range in.EvidenceIDs {
euuid, err := uuid.Parse(eid)
if err != nil {
return err
}
if err := tx.Create(&relational.CcfPoamItemEvidenceLink{PoamItemID: item.ID, EvidenceID: euuid}).Error; err != nil {
return err
}
}
for _, cr := range in.ControlRefs {
catID, err := uuid.Parse(cr.CatalogID)
if err != nil {
return err
}
if err := tx.Create(&relational.CcfPoamItemControlLink{
PoamItemID: item.ID,
CatalogID:  catID,
ControlID:  cr.ControlID,
}).Error; err != nil {
return err
}
}
for _, fid := range in.FindingIDs {
fuuid, err := uuid.Parse(fid)
if err != nil {
return err
}
if err := tx.Create(&relational.CcfPoamItemFindingLink{PoamItemID: item.ID, FindingID: fuuid}).Error; err != nil {
return err
}
}
return nil
})
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
h.db.Preload("Milestones", func(db *gorm.DB) *gorm.DB {
return db.Order("order_index ASC")
}).First(&item, "id = ?", item.ID)
return c.JSON(http.StatusCreated, GenericDataResponse[relational.CcfPoamItem]{Data: item})
}

// List godoc
//
//@SummaryList POAM items
//@DescriptionList POAM items with optional filters: status, sspId, riskId, dueBefore, overdueOnly, ownerRef.
//@TagsPOAM Items
//@Producejson
//@Paramstatusquerystringfalse"open|in-progress|completed|overdue"
//@ParamsspIdquerystringfalse"SSP UUID"
//@ParamriskIdquerystringfalse"Risk UUID"
//@ParamdueBeforequerystringfalse"RFC3339 timestamp"
//@ParamoverdueOnlyqueryboolfalse"true — items past planned_completion_date"
//@ParamownerRefquerystringfalse"UUID of primary_owner_user_id"
//@Success200{object}GenericDataListResponse[relational.CcfPoamItem]
//@Failure500{object}api.Error
//@Router/poam-items [get]
func (h *PoamItemsHandler) List(c echo.Context) error {
var items []relational.CcfPoamItem
q := h.db.Model(&relational.CcfPoamItem{})
if v := c.QueryParam("status"); v != "" {
q = q.Where("status = ?", v)
}
if v := c.QueryParam("sspId"); v != "" {
if id, err := uuid.Parse(v); err == nil {
q = q.Where("ssp_id = ?", id)
}
}
if v := c.QueryParam("ownerRef"); v != "" {
if id, err := uuid.Parse(v); err == nil {
q = q.Where("primary_owner_user_id = ?", id)
}
}
if v := c.QueryParam("dueBefore"); v != "" {
if t, err := time.Parse(time.RFC3339, v); err == nil {
q = q.Where("planned_completion_date IS NOT NULL AND planned_completion_date < ?", t)
}
}
if c.QueryParam("overdueOnly") == "true" {
now := time.Now().UTC()
q = q.Where("status IN ('open','in-progress') AND planned_completion_date IS NOT NULL AND planned_completion_date < ?", now)
}
if v := c.QueryParam("riskId"); v != "" {
if id, err := uuid.Parse(v); err == nil {
q = q.Joins("JOIN ccf_poam_item_risk_links rl ON rl.poam_item_id = ccf_poam_items.id AND rl.risk_id = ?", id)
}
}
if err := q.Find(&items).Error; err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItem]{Data: items})
}

// Get godoc
//
//@SummaryGet POAM item
//@DescriptionGet a single POAM item with its milestones and all link sets.
//@TagsPOAM Items
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@Success200{object}GenericDataResponse[PoamItemResponse]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Router/poam-items/{id} [get]
func (h *PoamItemsHandler) Get(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
var item relational.CcfPoamItem
if err := h.db.Preload("Milestones", func(db *gorm.DB) *gorm.DB {
return db.Order("order_index ASC")
}).First(&item, "id = ?", id).Error; err != nil {
return c.JSON(http.StatusNotFound, api.NewError(err))
}
var riskLinks []relational.CcfPoamItemRiskLink
h.db.Where("poam_item_id = ?", id).Find(&riskLinks)
var evidenceLinks []relational.CcfPoamItemEvidenceLink
h.db.Where("poam_item_id = ?", id).Find(&evidenceLinks)
var controlLinks []relational.CcfPoamItemControlLink
h.db.Where("poam_item_id = ?", id).Find(&controlLinks)
var findingLinks []relational.CcfPoamItemFindingLink
h.db.Where("poam_item_id = ?", id).Find(&findingLinks)
resp := PoamItemResponse{
CcfPoamItem:   item,
RiskLinks:     riskLinks,
EvidenceLinks: evidenceLinks,
ControlLinks:  controlLinks,
FindingLinks:  findingLinks,
}
return c.JSON(http.StatusOK, GenericDataResponse[PoamItemResponse]{Data: resp})
}

// Update godoc
//
//@SummaryUpdate POAM item
//@DescriptionUpdate scalar fields of a POAM item. Setting status to 'completed' automatically sets completed_at.
//@TagsPOAM Items
//@Acceptjson
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@ParambodybodyupdatePoamRequesttrue"Fields to update"
//@Success200{object}GenericDataResponse[relational.CcfPoamItem]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Failure500{object}api.Error
//@Router/poam-items/{id} [put]
func (h *PoamItemsHandler) Update(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var in updatePoamRequest
if err := c.Bind(&in); err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
updates := map[string]interface{}{}
if in.Title != nil {
updates["title"] = *in.Title
}
if in.Description != nil {
updates["description"] = *in.Description
}
if in.Status != nil {
updates["status"] = *in.Status
updates["last_status_change_at"] = time.Now().UTC()
if *in.Status == "completed" {
now := time.Now().UTC()
updates["completed_at"] = &now
}
}
if in.PrimaryOwnerUserID != nil {
ownerID, err := uuid.Parse(*in.PrimaryOwnerUserID)
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
updates["primary_owner_user_id"] = ownerID
}
if in.PlannedCompletionDate != nil {
updates["planned_completion_date"] = in.PlannedCompletionDate
}
if in.CompletedAt != nil {
updates["completed_at"] = in.CompletedAt
}
if in.AcceptanceRationale != nil {
updates["acceptance_rationale"] = *in.AcceptanceRationale
}
if err := h.db.Model(&relational.CcfPoamItem{}).Where("id = ?", id).Updates(updates).Error; err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
var out relational.CcfPoamItem
h.db.Preload("Milestones", func(db *gorm.DB) *gorm.DB {
return db.Order("order_index ASC")
}).First(&out, "id = ?", id)
return c.JSON(http.StatusOK, GenericDataResponse[relational.CcfPoamItem]{Data: out})
}

// Delete godoc
//
//@SummaryDelete POAM item
//@DescriptionDelete a POAM item and cascade-delete its milestones and all link records.
//@TagsPOAM Items
//@Paramidpathstringtrue"POAM item ID"
//@Success204"No Content"
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Failure500{object}api.Error
//@Router/poam-items/{id} [delete]
func (h *PoamItemsHandler) Delete(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
err = h.db.Transaction(func(tx *gorm.DB) error {
if err := tx.Where("poam_item_id = ?", id).Delete(&relational.CcfPoamItemRiskLink{}).Error; err != nil {
return err
}
if err := tx.Where("poam_item_id = ?", id).Delete(&relational.CcfPoamItemEvidenceLink{}).Error; err != nil {
return err
}
if err := tx.Where("poam_item_id = ?", id).Delete(&relational.CcfPoamItemControlLink{}).Error; err != nil {
return err
}
if err := tx.Where("poam_item_id = ?", id).Delete(&relational.CcfPoamItemFindingLink{}).Error; err != nil {
return err
}
if err := tx.Where("poam_item_id = ?", id).Delete(&relational.CcfPoamItemMilestone{}).Error; err != nil {
return err
}
return tx.Delete(&relational.CcfPoamItem{}, "id = ?", id).Error
})
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
return c.NoContent(http.StatusNoContent)
}

// ListMilestones godoc
//
//@SummaryList milestones
//@DescriptionList all milestones for a POAM item, ordered by order_index.
//@TagsPOAM Items
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@Success200{object}GenericDataListResponse[relational.CcfPoamItemMilestone]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Failure500{object}api.Error
//@Router/poam-items/{id}/milestones [get]
func (h *PoamItemsHandler) ListMilestones(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var ms []relational.CcfPoamItemMilestone
if err := h.db.Where("poam_item_id = ?", id).Order("order_index ASC").Find(&ms).Error; err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItemMilestone]{Data: ms})
}

// AddMilestone godoc
//
//@SummaryAdd milestone
//@DescriptionAdd a milestone to a POAM item.
//@TagsPOAM Items
//@Acceptjson
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@ParambodybodycreateMilestoneRequesttrue"Milestone payload"
//@Success201{object}GenericDataResponse[relational.CcfPoamItemMilestone]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Failure500{object}api.Error
//@Router/poam-items/{id}/milestones [post]
func (h *PoamItemsHandler) AddMilestone(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var in createMilestoneRequest
if err := c.Bind(&in); err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
m := relational.CcfPoamItemMilestone{
ID:                      uuid.New(),
PoamItemID:              id,
Title:                   in.Title,
Description:             in.Description,
Status:                  in.Status,
ScheduledCompletionDate: in.ScheduledCompletionDate,
OrderIndex:              in.OrderIndex,
}
if err := h.db.Create(&m).Error; err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
return c.JSON(http.StatusCreated, GenericDataResponse[relational.CcfPoamItemMilestone]{Data: m})
}

// UpdateMilestone godoc
//
//@SummaryUpdate milestone
//@DescriptionUpdate milestone fields. When status becomes 'completed', completion_date is set automatically.
//@TagsPOAM Items
//@Acceptjson
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@ParammilestoneIdpathstringtrue"Milestone ID"
//@ParambodybodyupdateMilestoneRequesttrue"Fields to update"
//@Success200{object}GenericDataResponse[relational.CcfPoamItemMilestone]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Failure500{object}api.Error
//@Router/poam-items/{id}/milestones/{milestoneId} [put]
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
updates := map[string]interface{}{}
if in.Title != nil {
updates["title"] = *in.Title
}
if in.Description != nil {
updates["description"] = *in.Description
}
if in.Status != nil {
updates["status"] = *in.Status
if *in.Status == "completed" {
now := time.Now().UTC()
updates["completion_date"] = &now
}
}
if in.ScheduledCompletionDate != nil {
updates["scheduled_completion_date"] = in.ScheduledCompletionDate
}
if in.OrderIndex != nil {
updates["order_index"] = *in.OrderIndex
}
result := h.db.Model(&relational.CcfPoamItemMilestone{}).
Where("poam_item_id = ? AND id = ?", id, mid).
Updates(updates)
if result.Error != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(result.Error))
}
if result.RowsAffected == 0 {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var out relational.CcfPoamItemMilestone
h.db.First(&out, "id = ?", mid)
return c.JSON(http.StatusOK, GenericDataResponse[relational.CcfPoamItemMilestone]{Data: out})
}

// DeleteMilestone godoc
//
//@SummaryDelete milestone
//@TagsPOAM Items
//@Paramidpathstringtrue"POAM item ID"
//@ParammilestoneIdpathstringtrue"Milestone ID"
//@Success204"No Content"
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Failure500{object}api.Error
//@Router/poam-items/{id}/milestones/{milestoneId} [delete]
func (h *PoamItemsHandler) DeleteMilestone(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
mid, err := uuid.Parse(c.Param("milestoneId"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
result := h.db.Where("poam_item_id = ? AND id = ?", id, mid).Delete(&relational.CcfPoamItemMilestone{})
if result.Error != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(result.Error))
}
if result.RowsAffected == 0 {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
return c.NoContent(http.StatusNoContent)
}

// ListRisks godoc
//
//@SummaryList linked risks
//@TagsPOAM Items
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@Success200{object}GenericDataListResponse[relational.CcfPoamItemRiskLink]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Router/poam-items/{id}/risks [get]
func (h *PoamItemsHandler) ListRisks(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var links []relational.CcfPoamItemRiskLink
h.db.Where("poam_item_id = ?", id).Find(&links)
return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItemRiskLink]{Data: links})
}

// ListEvidence godoc
//
//@SummaryList linked evidence
//@TagsPOAM Items
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@Success200{object}GenericDataListResponse[relational.CcfPoamItemEvidenceLink]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Router/poam-items/{id}/evidence [get]
func (h *PoamItemsHandler) ListEvidence(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var links []relational.CcfPoamItemEvidenceLink
h.db.Where("poam_item_id = ?", id).Find(&links)
return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItemEvidenceLink]{Data: links})
}

// ListControls godoc
//
//@SummaryList linked controls
//@TagsPOAM Items
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@Success200{object}GenericDataListResponse[relational.CcfPoamItemControlLink]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Router/poam-items/{id}/controls [get]
func (h *PoamItemsHandler) ListControls(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var links []relational.CcfPoamItemControlLink
h.db.Where("poam_item_id = ?", id).Find(&links)
return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItemControlLink]{Data: links})
}

// ListFindings godoc
//
//@SummaryList linked findings
//@TagsPOAM Items
//@Producejson
//@Paramidpathstringtrue"POAM item ID"
//@Success200{object}GenericDataListResponse[relational.CcfPoamItemFindingLink]
//@Failure400{object}api.Error
//@Failure404{object}api.Error
//@Router/poam-items/{id}/findings [get]
func (h *PoamItemsHandler) ListFindings(c echo.Context) error {
id, err := uuid.Parse(c.Param("id"))
if err != nil {
return c.JSON(http.StatusBadRequest, api.NewError(err))
}
exists, err := h.itemExists(id)
if err != nil {
return c.JSON(http.StatusInternalServerError, api.NewError(err))
}
if !exists {
return c.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
}
var links []relational.CcfPoamItemFindingLink
h.db.Where("poam_item_id = ?", id).Find(&links)
return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItemFindingLink]{Data: links})
}
