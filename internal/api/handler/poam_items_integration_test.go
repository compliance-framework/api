//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/gorm/clause"
)

// ---------------------------------------------------------------------------
// Suite bootstrap
// ---------------------------------------------------------------------------

func TestPoamItemsApi(t *testing.T) {
	suite.Run(t, new(PoamItemsApiIntegrationSuite))
}

type PoamItemsApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *PoamItemsApiIntegrationSuite) newServer() *api.Server {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, nil)
	return server
}

// authedReq creates an authenticated HTTP request with a valid JWT token.
// body may be nil for requests without a payload (GET, DELETE).
func (suite *PoamItemsApiIntegrationSuite) authedReq(method, path string, body []byte) (*httptest.ResponseRecorder, *http.Request) {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader([]byte{})
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
	return rec, req
}

// ensureSSP seeds a SystemSecurityPlan row so that the Create handler's
// EnsureSSPExists check passes. The SSP record only needs an ID.
func (suite *PoamItemsApiIntegrationSuite) ensureSSP(id uuid.UUID) {
	ssp := relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &id}}
	suite.Require().NoError(suite.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&ssp).Error)
}

// seedItem inserts a PoamItem directly into the DB, bypassing the API.
func (suite *PoamItemsApiIntegrationSuite) seedItem(sspID uuid.UUID, title, status string) poamsvc.PoamItem {
	item := poamsvc.PoamItem{
		ID:                 uuid.New(),
		SspID:              sspID,
		Title:              title,
		Description:        "seeded for test",
		Status:             status,
		SourceType:         string(poamsvc.PoamItemSourceTypeManual),
		LastStatusChangeAt: time.Now().UTC(),
	}
	suite.Require().NoError(suite.DB.Create(&item).Error)
	return item
}

// seedMilestone inserts a PoamItemMilestone directly into the DB.
func (suite *PoamItemsApiIntegrationSuite) seedMilestone(poamID uuid.UUID, title, status string, orderIdx int) poamsvc.PoamItemMilestone {
	m := poamsvc.PoamItemMilestone{
		ID:         uuid.New(),
		PoamItemID: poamID,
		Title:      title,
		Status:     string(poamsvc.MilestoneStatus(status)),
		OrderIndex: orderIdx,
	}
	suite.Require().NoError(suite.DB.Create(&m).Error)
	return m
}

// ---------------------------------------------------------------------------
// POST /poam-items
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestCreate_MinimalPayload() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	suite.ensureSSP(sspID)
	body := createPoamItemRequest{
		SspID:       sspID.String(),
		Title:       "Remediate secret scanning",
		Description: "Enable secret scanning across all repos",
		Status:      "open",
	}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, "/api/poam-items", raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var resp GenericDataResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(suite.T(), "Remediate secret scanning", resp.Data.Title)
	assert.Equal(suite.T(), "open", resp.Data.Status)
	assert.Equal(suite.T(), "manual", resp.Data.SourceType)
	assert.NotEqual(suite.T(), uuid.Nil, resp.Data.ID)
}

func (suite *PoamItemsApiIntegrationSuite) TestCreate_WithMilestonesAndLinks() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	suite.ensureSSP(sspID)
	due := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	body := createPoamItemRequest{
		SspID:       sspID.String(),
		Title:       "Patch OS vulnerabilities",
		Description: "Apply all critical OS patches",
		Status:      "open",
		SourceType:  "risk-promotion",
		Milestones: []createMilestoneRequest{
			{Title: "Patch staging", Status: "planned", ScheduledCompletionDate: &due, OrderIndex: 0},
			{Title: "Patch production", Status: "planned", OrderIndex: 1},
		},
	}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, "/api/poam-items", raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var resp GenericDataResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(suite.T(), "risk-promotion", resp.Data.SourceType)
	assert.Len(suite.T(), resp.Data.Milestones, 2)
	assert.Equal(suite.T(), "Patch staging", resp.Data.Milestones[0].Title)
	assert.Equal(suite.T(), "Patch production", resp.Data.Milestones[1].Title)
}

func (suite *PoamItemsApiIntegrationSuite) TestCreate_WithRiskLinks() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	suite.ensureSSP(sspID)
	riskID := uuid.New()
	body := createPoamItemRequest{
		SspID:       sspID.String(),
		Title:       "Linked to risk",
		Description: "POAM item linked to a risk",
		Status:      "open",
		RiskIDs:     []string{riskID.String()},
	}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, "/api/poam-items", raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var resp GenericDataResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	var links []poamsvc.PoamItemRiskLink
	suite.Require().NoError(suite.DB.Where("poam_item_id = ?", resp.Data.ID).Find(&links).Error)
	assert.Len(suite.T(), links, 1)
	assert.Equal(suite.T(), riskID, links[0].RiskID)
}

func (suite *PoamItemsApiIntegrationSuite) TestCreate_WithAllLinkTypes() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	suite.ensureSSP(sspID)
	riskID := uuid.New()
	evidenceID := uuid.New()
	findingID := uuid.New()
	catalogID := uuid.New()
	body := createPoamItemRequest{
		SspID:       sspID.String(),
		Title:       "Full link test",
		Description: "POAM item with all link types",
		Status:      "open",
		RiskIDs:     []string{riskID.String()},
		EvidenceIDs: []string{evidenceID.String()},
		FindingIDs:  []string{findingID.String()},
		ControlRefs: []poamControlRefRequest{{CatalogID: catalogID.String(), ControlID: "AC-1"}},
	}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, "/api/poam-items", raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var resp GenericDataResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	itemID := resp.Data.ID
	var riskLinks []poamsvc.PoamItemRiskLink
	suite.DB.Where("poam_item_id = ?", itemID).Find(&riskLinks)
	assert.Len(suite.T(), riskLinks, 1)
	var evidenceLinks []poamsvc.PoamItemEvidenceLink
	suite.DB.Where("poam_item_id = ?", itemID).Find(&evidenceLinks)
	assert.Len(suite.T(), evidenceLinks, 1)
	var findingLinks []poamsvc.PoamItemFindingLink
	suite.DB.Where("poam_item_id = ?", itemID).Find(&findingLinks)
	assert.Len(suite.T(), findingLinks, 1)
	var controlLinks []poamsvc.PoamItemControlLink
	suite.DB.Where("poam_item_id = ?", itemID).Find(&controlLinks)
	assert.Len(suite.T(), controlLinks, 1)
	assert.Equal(suite.T(), "AC-1", controlLinks[0].ControlID)
}

func (suite *PoamItemsApiIntegrationSuite) TestCreate_InvalidSspID() {
	suite.Require().NoError(suite.Migrator.Refresh())
	// No SSP seeded — invalid UUID should be rejected before the DB lookup.
	body := map[string]interface{}{"sspId": "not-a-uuid", "title": "X", "status": "open"}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, "/api/poam-items", raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// GET /poam-items (list with filters)
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestList_NoFilter() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	suite.seedItem(sspID, "Item A", "open")
	suite.seedItem(sspID, "Item B", "in-progress")
	suite.seedItem(uuid.New(), "Item C", "completed")
	rec, req := suite.authedReq(http.MethodGet, "/api/poam-items", nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 3)
}

func (suite *PoamItemsApiIntegrationSuite) TestList_FilterByStatus() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	suite.seedItem(sspID, "Open item", "open")
	suite.seedItem(sspID, "In-progress item", "in-progress")
	suite.seedItem(sspID, "Completed item", "completed")
	rec, req := suite.authedReq(http.MethodGet, "/api/poam-items?status=open", nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
	assert.Equal(suite.T(), "open", resp.Data[0].Status)
}

func (suite *PoamItemsApiIntegrationSuite) TestList_FilterBySspId() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspA := uuid.New()
	sspB := uuid.New()
	suite.seedItem(sspA, "SSP-A item 1", "open")
	suite.seedItem(sspA, "SSP-A item 2", "open")
	suite.seedItem(sspB, "SSP-B item", "open")
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items?sspId=%s", sspA), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 2)
	for _, item := range resp.Data {
		assert.Equal(suite.T(), sspA, item.SspID)
	}
}

func (suite *PoamItemsApiIntegrationSuite) TestList_FilterByRiskId() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	riskID := uuid.New()
	item1 := suite.seedItem(sspID, "Linked to risk", "open")
	suite.seedItem(sspID, "Not linked", "open")
	suite.Require().NoError(suite.DB.Create(&poamsvc.PoamItemRiskLink{PoamItemID: item1.ID, RiskID: riskID}).Error)
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items?riskId=%s", riskID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
	assert.Equal(suite.T(), item1.ID, resp.Data[0].ID)
}

func (suite *PoamItemsApiIntegrationSuite) TestList_FilterByDueBefore() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	past := time.Now().Add(-24 * time.Hour).UTC()
	future := time.Now().Add(30 * 24 * time.Hour).UTC()
	itemPast := poamsvc.PoamItem{
		ID: uuid.New(), SspID: sspID, Title: "Past due", Description: "d",
		Status: string(poamsvc.PoamItemStatusOpen), SourceType: string(poamsvc.PoamItemSourceTypeManual),
		PlannedCompletionDate: &past, LastStatusChangeAt: time.Now().UTC(),
	}
	itemFuture := poamsvc.PoamItem{
		ID: uuid.New(), SspID: sspID, Title: "Future due", Description: "d",
		Status: string(poamsvc.PoamItemStatusOpen), SourceType: string(poamsvc.PoamItemSourceTypeManual),
		PlannedCompletionDate: &future, LastStatusChangeAt: time.Now().UTC(),
	}
	suite.Require().NoError(suite.DB.Create(&itemPast).Error)
	suite.Require().NoError(suite.DB.Create(&itemFuture).Error)
	cutoff := time.Now().UTC().Format(time.RFC3339)
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items?dueBefore=%s", cutoff), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
	assert.Equal(suite.T(), itemPast.ID, resp.Data[0].ID)
}

func (suite *PoamItemsApiIntegrationSuite) TestList_FilterOverdueOnly() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	past := time.Now().Add(-24 * time.Hour).UTC()
	future := time.Now().Add(30 * 24 * time.Hour).UTC()
	overdueItem := poamsvc.PoamItem{
		ID: uuid.New(), SspID: sspID, Title: "Overdue open", Description: "d",
		Status: string(poamsvc.PoamItemStatusOpen), SourceType: string(poamsvc.PoamItemSourceTypeManual),
		PlannedCompletionDate: &past, LastStatusChangeAt: time.Now().UTC(),
	}
	completedPast := poamsvc.PoamItem{
		ID: uuid.New(), SspID: sspID, Title: "Completed past", Description: "d",
		Status: string(poamsvc.PoamItemStatusCompleted), SourceType: string(poamsvc.PoamItemSourceTypeManual),
		PlannedCompletionDate: &past, LastStatusChangeAt: time.Now().UTC(),
	}
	futureItem := poamsvc.PoamItem{
		ID: uuid.New(), SspID: sspID, Title: "Future open", Description: "d",
		Status: string(poamsvc.PoamItemStatusOpen), SourceType: string(poamsvc.PoamItemSourceTypeManual),
		PlannedCompletionDate: &future, LastStatusChangeAt: time.Now().UTC(),
	}
	suite.Require().NoError(suite.DB.Create(&overdueItem).Error)
	suite.Require().NoError(suite.DB.Create(&completedPast).Error)
	suite.Require().NoError(suite.DB.Create(&futureItem).Error)
	rec, req := suite.authedReq(http.MethodGet, "/api/poam-items?overdueOnly=true", nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
	assert.Equal(suite.T(), overdueItem.ID, resp.Data[0].ID)
}

func (suite *PoamItemsApiIntegrationSuite) TestList_FilterByOwnerRef() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	ownerID := uuid.New()
	otherOwnerID := uuid.New()
	itemOwned := poamsvc.PoamItem{
		ID: uuid.New(), SspID: sspID, Title: "Owned", Description: "d",
		Status: string(poamsvc.PoamItemStatusOpen), SourceType: string(poamsvc.PoamItemSourceTypeManual),
		PrimaryOwnerUserID: &ownerID, LastStatusChangeAt: time.Now().UTC(),
	}
	itemOther := poamsvc.PoamItem{
		ID: uuid.New(), SspID: sspID, Title: "Other owner", Description: "d",
		Status: string(poamsvc.PoamItemStatusOpen), SourceType: string(poamsvc.PoamItemSourceTypeManual),
		PrimaryOwnerUserID: &otherOwnerID, LastStatusChangeAt: time.Now().UTC(),
	}
	suite.Require().NoError(suite.DB.Create(&itemOwned).Error)
	suite.Require().NoError(suite.DB.Create(&itemOther).Error)
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items?ownerRef=%s", ownerID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
	assert.Equal(suite.T(), itemOwned.ID, resp.Data[0].ID)
}

// ---------------------------------------------------------------------------
// GET /poam-items/:id
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestGet_Exists() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Get test item", "open")
	suite.seedMilestone(item.ID, "Milestone A", "planned", 0)
	suite.seedMilestone(item.ID, "Milestone B", "planned", 1)
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(suite.T(), item.ID, resp.Data.ID)
	assert.Len(suite.T(), resp.Data.Milestones, 2)
	assert.Equal(suite.T(), "Milestone A", resp.Data.Milestones[0].Title)
	assert.Equal(suite.T(), "Milestone B", resp.Data.Milestones[1].Title)
}

func (suite *PoamItemsApiIntegrationSuite) TestGet_NotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s", uuid.New()), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

func (suite *PoamItemsApiIntegrationSuite) TestGet_InvalidUUID() {
	suite.Require().NoError(suite.Migrator.Refresh())
	rec, req := suite.authedReq(http.MethodGet, "/api/poam-items/not-a-uuid", nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)
}

func (suite *PoamItemsApiIntegrationSuite) TestGet_IncludesAllLinkSets() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Link sets test", "open")
	riskID := uuid.New()
	evidenceID := uuid.New()
	findingID := uuid.New()
	catalogID := uuid.New()
	suite.DB.Create(&poamsvc.PoamItemRiskLink{PoamItemID: item.ID, RiskID: riskID})
	suite.DB.Create(&poamsvc.PoamItemEvidenceLink{PoamItemID: item.ID, EvidenceID: evidenceID})
	suite.DB.Create(&poamsvc.PoamItemFindingLink{PoamItemID: item.ID, FindingID: findingID})
	suite.DB.Create(&poamsvc.PoamItemControlLink{PoamItemID: item.ID, CatalogID: catalogID, ControlID: "AC-2"})
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data.RiskLinks, 1)
	assert.Len(suite.T(), resp.Data.EvidenceLinks, 1)
	assert.Len(suite.T(), resp.Data.FindingLinks, 1)
	assert.Len(suite.T(), resp.Data.ControlLinks, 1)
}

// ---------------------------------------------------------------------------
// PUT /poam-items/:id
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestUpdate_ScalarFields() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Original title", "open")
	newTitle := "Updated title"
	newDesc := "Updated description"
	body := updatePoamItemRequest{Title: &newTitle, Description: &newDesc}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPut, fmt.Sprintf("/api/poam-items/%s", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataResponse[poamItemResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(suite.T(), "Updated title", resp.Data.Title)
	assert.Equal(suite.T(), "Updated description", resp.Data.Description)
}

func (suite *PoamItemsApiIntegrationSuite) TestUpdate_StatusToCompleted_SetsCompletedAt() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Will complete", "open")
	newStatus := "completed"
	body := updatePoamItemRequest{Status: &newStatus}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPut, fmt.Sprintf("/api/poam-items/%s", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var updated poamsvc.PoamItem
	suite.Require().NoError(suite.DB.First(&updated, "id = ?", item.ID).Error)
	assert.Equal(suite.T(), string(poamsvc.PoamItemStatusCompleted), updated.Status)
	assert.NotNil(suite.T(), updated.CompletedAt)
}

func (suite *PoamItemsApiIntegrationSuite) TestUpdate_StatusChange_SetsLastStatusChangeAt() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Status change", "open")
	originalChangeAt := item.LastStatusChangeAt
	time.Sleep(10 * time.Millisecond)
	newStatus := "in-progress"
	body := updatePoamItemRequest{Status: &newStatus}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPut, fmt.Sprintf("/api/poam-items/%s", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var updated poamsvc.PoamItem
	suite.Require().NoError(suite.DB.First(&updated, "id = ?", item.ID).Error)
	assert.True(suite.T(), updated.LastStatusChangeAt.After(originalChangeAt))
}

func (suite *PoamItemsApiIntegrationSuite) TestUpdate_NotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	newTitle := "Ghost"
	body := updatePoamItemRequest{Title: &newTitle}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPut, fmt.Sprintf("/api/poam-items/%s", uuid.New()), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// DELETE /poam-items/:id
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestDelete_CascadesAllLinks() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "To delete", "open")
	suite.seedMilestone(item.ID, "MS1", "planned", 0)
	riskID := uuid.New()
	suite.DB.Create(&poamsvc.PoamItemRiskLink{PoamItemID: item.ID, RiskID: riskID})
	evidenceID := uuid.New()
	suite.DB.Create(&poamsvc.PoamItemEvidenceLink{PoamItemID: item.ID, EvidenceID: evidenceID})
	rec, req := suite.authedReq(http.MethodDelete, fmt.Sprintf("/api/poam-items/%s", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItem{}).Where("id = ?", item.ID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
	suite.DB.Model(&poamsvc.PoamItemMilestone{}).Where("poam_item_id = ?", item.ID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
	suite.DB.Model(&poamsvc.PoamItemRiskLink{}).Where("poam_item_id = ?", item.ID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
	suite.DB.Model(&poamsvc.PoamItemEvidenceLink{}).Where("poam_item_id = ?", item.ID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestDelete_NotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	rec, req := suite.authedReq(http.MethodDelete, fmt.Sprintf("/api/poam-items/%s", uuid.New()), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// GET /poam-items/:id/milestones
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestListMilestones_OrderedByIndex() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "MS order test", "open")
	suite.seedMilestone(item.ID, "Third", "planned", 2)
	suite.seedMilestone(item.ID, "First", "planned", 0)
	suite.seedMilestone(item.ID, "Second", "planned", 1)
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s/milestones", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[milestoneResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 3)
	assert.Equal(suite.T(), "First", resp.Data[0].Title)
	assert.Equal(suite.T(), "Second", resp.Data[1].Title)
	assert.Equal(suite.T(), "Third", resp.Data[2].Title)
}

func (suite *PoamItemsApiIntegrationSuite) TestListMilestones_ParentNotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s/milestones", uuid.New()), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// POST /poam-items/:id/milestones
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestAddMilestone() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Add milestone test", "open")
	due := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
	body := createMilestoneRequest{
		Title:                   "Deploy to staging",
		Description:             "Deploy patched version to staging",
		Status:                  "planned",
		ScheduledCompletionDate: &due,
		OrderIndex:              0,
	}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, fmt.Sprintf("/api/poam-items/%s/milestones", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var resp GenericDataResponse[milestoneResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(suite.T(), "Deploy to staging", resp.Data.Title)
	assert.Equal(suite.T(), "planned", resp.Data.Status)
	assert.Equal(suite.T(), item.ID, resp.Data.PoamItemID)
}

func (suite *PoamItemsApiIntegrationSuite) TestAddMilestone_ParentNotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	body := createMilestoneRequest{Title: "Ghost MS", Status: "planned"}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, fmt.Sprintf("/api/poam-items/%s/milestones", uuid.New()), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// PUT /poam-items/:id/milestones/:milestoneId
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestUpdateMilestone_MarkCompleted_SetsCompletionDate() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Milestone complete test", "open")
	ms := suite.seedMilestone(item.ID, "Enable scanning", "planned", 0)
	newStatus := "completed"
	body := updateMilestoneRequest{Status: &newStatus}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(
		http.MethodPut,
		fmt.Sprintf("/api/poam-items/%s/milestones/%s", item.ID, ms.ID),
		raw,
	)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var updated poamsvc.PoamItemMilestone
	suite.Require().NoError(suite.DB.First(&updated, "id = ?", ms.ID).Error)
	assert.Equal(suite.T(), string(poamsvc.MilestoneStatusCompleted), updated.Status)
	assert.NotNil(suite.T(), updated.CompletionDate)
}

func (suite *PoamItemsApiIntegrationSuite) TestUpdateMilestone_UpdateTitle() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "MS title update", "open")
	ms := suite.seedMilestone(item.ID, "Old title", "planned", 0)
	newTitle := "New title"
	body := updateMilestoneRequest{Title: &newTitle}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(
		http.MethodPut,
		fmt.Sprintf("/api/poam-items/%s/milestones/%s", item.ID, ms.ID),
		raw,
	)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataResponse[milestoneResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(suite.T(), "New title", resp.Data.Title)
}

func (suite *PoamItemsApiIntegrationSuite) TestUpdateMilestone_UpdateOrderIndex() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "MS order update", "open")
	ms := suite.seedMilestone(item.ID, "Reorder me", "planned", 0)
	newOrder := 5
	body := updateMilestoneRequest{OrderIndex: &newOrder}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(
		http.MethodPut,
		fmt.Sprintf("/api/poam-items/%s/milestones/%s", item.ID, ms.ID),
		raw,
	)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataResponse[milestoneResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(suite.T(), 5, resp.Data.OrderIndex)
}

func (suite *PoamItemsApiIntegrationSuite) TestUpdateMilestone_NotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Parent exists", "open")
	newStatus := "completed"
	body := updateMilestoneRequest{Status: &newStatus}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(
		http.MethodPut,
		fmt.Sprintf("/api/poam-items/%s/milestones/%s", item.ID, uuid.New()),
		raw,
	)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// DELETE /poam-items/:id/milestones/:milestoneId
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestDeleteMilestone() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Delete MS test", "open")
	ms := suite.seedMilestone(item.ID, "To delete", "planned", 0)
	rec, req := suite.authedReq(
		http.MethodDelete,
		fmt.Sprintf("/api/poam-items/%s/milestones/%s", item.ID, ms.ID),
		nil,
	)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemMilestone{}).Where("id = ?", ms.ID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestDeleteMilestone_NotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Parent exists", "open")
	rec, req := suite.authedReq(
		http.MethodDelete,
		fmt.Sprintf("/api/poam-items/%s/milestones/%s", item.ID, uuid.New()),
		nil,
	)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// Link sub-resource endpoints — GET
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestListRisks() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Risk list test", "open")
	suite.DB.Create(&poamsvc.PoamItemRiskLink{PoamItemID: item.ID, RiskID: uuid.New()})
	suite.DB.Create(&poamsvc.PoamItemRiskLink{PoamItemID: item.ID, RiskID: uuid.New()})
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s/risks", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamsvc.PoamItemRiskLink]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 2)
}

func (suite *PoamItemsApiIntegrationSuite) TestListEvidence() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Evidence list test", "open")
	suite.DB.Create(&poamsvc.PoamItemEvidenceLink{PoamItemID: item.ID, EvidenceID: uuid.New()})
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s/evidence", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamsvc.PoamItemEvidenceLink]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
}

func (suite *PoamItemsApiIntegrationSuite) TestListControls() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Control list test", "open")
	suite.DB.Create(&poamsvc.PoamItemControlLink{PoamItemID: item.ID, CatalogID: uuid.New(), ControlID: "SI-2"})
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s/controls", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamsvc.PoamItemControlLink]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
	assert.Equal(suite.T(), "SI-2", resp.Data[0].ControlID)
}

func (suite *PoamItemsApiIntegrationSuite) TestListFindings() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Finding list test", "open")
	suite.DB.Create(&poamsvc.PoamItemFindingLink{PoamItemID: item.ID, FindingID: uuid.New()})
	rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s/findings", item.ID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	var resp GenericDataListResponse[poamsvc.PoamItemFindingLink]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(suite.T(), resp.Data, 1)
}

func (suite *PoamItemsApiIntegrationSuite) TestListLinks_ParentNotFound() {
	suite.Require().NoError(suite.Migrator.Refresh())
	ghostID := uuid.New()
	for _, path := range []string{"risks", "evidence", "controls", "findings"} {
		rec, req := suite.authedReq(http.MethodGet, fmt.Sprintf("/api/poam-items/%s/%s", ghostID, path), nil)
		suite.newServer().E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusNotFound, rec.Code, "expected 404 for /poam-items/:id/%s with unknown parent", path)
	}
}

// ---------------------------------------------------------------------------
// Link sub-resource endpoints — POST / DELETE
// ---------------------------------------------------------------------------

func (suite *PoamItemsApiIntegrationSuite) TestAddRiskLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Add risk link test", "open")
	riskID := uuid.New()
	body := addLinkRequest{ID: riskID.String()}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, fmt.Sprintf("/api/poam-items/%s/risks", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemRiskLink{}).Where("poam_item_id = ? AND risk_id = ?", item.ID, riskID).Count(&count)
	assert.Equal(suite.T(), int64(1), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestDeleteRiskLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Delete risk link test", "open")
	riskID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&poamsvc.PoamItemRiskLink{PoamItemID: item.ID, RiskID: riskID}).Error)
	rec, req := suite.authedReq(http.MethodDelete, fmt.Sprintf("/api/poam-items/%s/risks/%s", item.ID, riskID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemRiskLink{}).Where("poam_item_id = ? AND risk_id = ?", item.ID, riskID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestAddEvidenceLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Add evidence link test", "open")
	evidenceID := uuid.New()
	body := addLinkRequest{ID: evidenceID.String()}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, fmt.Sprintf("/api/poam-items/%s/evidence", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemEvidenceLink{}).Where("poam_item_id = ? AND evidence_id = ?", item.ID, evidenceID).Count(&count)
	assert.Equal(suite.T(), int64(1), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestDeleteEvidenceLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Delete evidence link test", "open")
	evidenceID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&poamsvc.PoamItemEvidenceLink{PoamItemID: item.ID, EvidenceID: evidenceID}).Error)
	rec, req := suite.authedReq(http.MethodDelete, fmt.Sprintf("/api/poam-items/%s/evidence/%s", item.ID, evidenceID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemEvidenceLink{}).Where("poam_item_id = ? AND evidence_id = ?", item.ID, evidenceID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestAddFindingLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Add finding link test", "open")
	findingID := uuid.New()
	body := addLinkRequest{ID: findingID.String()}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, fmt.Sprintf("/api/poam-items/%s/findings", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemFindingLink{}).Where("poam_item_id = ? AND finding_id = ?", item.ID, findingID).Count(&count)
	assert.Equal(suite.T(), int64(1), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestDeleteFindingLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Delete finding link test", "open")
	findingID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&poamsvc.PoamItemFindingLink{PoamItemID: item.ID, FindingID: findingID}).Error)
	rec, req := suite.authedReq(http.MethodDelete, fmt.Sprintf("/api/poam-items/%s/findings/%s", item.ID, findingID), nil)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemFindingLink{}).Where("poam_item_id = ? AND finding_id = ?", item.ID, findingID).Count(&count)
	assert.Equal(suite.T(), int64(0), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestAddControlLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Add control link test", "open")
	catalogID := uuid.New()
	body := poamControlRefRequest{CatalogID: catalogID.String(), ControlID: "AC-3"}
	raw, _ := json.Marshal(body)
	rec, req := suite.authedReq(http.MethodPost, fmt.Sprintf("/api/poam-items/%s/controls", item.ID), raw)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemControlLink{}).Where("poam_item_id = ? AND control_id = ?", item.ID, "AC-3").Count(&count)
	assert.Equal(suite.T(), int64(1), count)
}

func (suite *PoamItemsApiIntegrationSuite) TestDeleteControlLink() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	item := suite.seedItem(sspID, "Delete control link test", "open")
	catalogID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&poamsvc.PoamItemControlLink{PoamItemID: item.ID, CatalogID: catalogID, ControlID: "AC-4"}).Error)
	rec, req := suite.authedReq(
		http.MethodDelete,
		fmt.Sprintf("/api/poam-items/%s/controls/%s/AC-4", item.ID, catalogID),
		nil,
	)
	suite.newServer().E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)
	var count int64
	suite.DB.Model(&poamsvc.PoamItemControlLink{}).Where("poam_item_id = ? AND catalog_id = ? AND control_id = ?", item.ID, catalogID, "AC-4").Count(&count)
	assert.Equal(suite.T(), int64(0), count)
}

// ---------------------------------------------------------------------------
// Uniqueness constraint — duplicate risk link
// ---------------------------------------------------------------------------

// TestCreate_DuplicateRiskLink_IsIdempotent verifies that POSTing the same risk
// link twice returns HTTP 201 both times (ON CONFLICT DO NOTHING — same pattern
// as the Risk service). The unique constraint still exists in the DB; the
// service simply re-fetches and returns the existing record on conflict.
func (suite *PoamItemsApiIntegrationSuite) TestCreate_DuplicateRiskLink_IsIdempotent() {
	suite.Require().NoError(suite.Migrator.Refresh())
	sspID := uuid.New()
	riskID := uuid.New()
	item := suite.seedItem(sspID, "Dup risk test", "open")

	body := fmt.Sprintf(`{"id":"%s"}`, riskID)

	// First POST — creates the link.
	rec1, req1 := suite.authedReq(http.MethodPost,
		fmt.Sprintf("/api/poam-items/%s/risks", item.ID), []byte(body))
	suite.newServer().E().ServeHTTP(rec1, req1)
	assert.Equal(suite.T(), http.StatusCreated, rec1.Code, "first POST should return 201")

	// Second POST — idempotent, should also return 201.
	rec2, req2 := suite.authedReq(http.MethodPost,
		fmt.Sprintf("/api/poam-items/%s/risks", item.ID), []byte(body))
	suite.newServer().E().ServeHTTP(rec2, req2)
	assert.Equal(suite.T(), http.StatusCreated, rec2.Code, "duplicate POST should be idempotent (201)")

	// Verify only one link exists in the DB.
	var count int64
	suite.DB.Model(&poamsvc.PoamItemRiskLink{}).Where("poam_item_id = ? AND risk_id = ?", item.ID, riskID).Count(&count)
	assert.Equal(suite.T(), int64(1), count, "only one risk link should exist")
}

