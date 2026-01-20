//go:build integration

package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

type InventoryApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	handler         *InventoryHandler
	sspHandler      *SystemSecurityPlanHandler
	poamHandler     *PlanOfActionAndMilestonesHandler
	evidenceHandler *handler.EvidenceHandler
	server          *api.Server
}

func (suite *InventoryApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	// Initialize handlers
	logger := zap.NewNop().Sugar()
	suite.handler = NewInventoryHandler(logger, suite.DB)
	suite.sspHandler = NewSystemSecurityPlanHandler(logger, suite.DB)
	suite.poamHandler = NewPlanOfActionAndMilestonesHandler(logger, suite.DB)
	suite.evidenceHandler = handler.NewEvidenceHandler(logger, suite.DB, suite.Config)

	// Initialize server
	metrics := api.NewMetricsHandler(context.Background(), logger)
	suite.server = api.NewServer(context.Background(), logger, suite.Config, metrics)

	// Register handlers
	apiGroup := suite.server.API()

	// Register inventory handler with auth middleware
	inventoryGroup := apiGroup.Group("/oscal/inventory")
	inventoryGroup.Use(middleware.JWTMiddleware(suite.Config.JWTPublicKey))
	suite.handler.Register(inventoryGroup)

	// Register SSP handler
	sspGroup := apiGroup.Group("/oscal/system-security-plans")
	sspGroup.Use(middleware.JWTMiddleware(suite.Config.JWTPublicKey))
	suite.sspHandler.Register(sspGroup)

	// Register POAM handler
	poamGroup := apiGroup.Group("/oscal/plan-of-action-and-milestones")
	poamGroup.Use(middleware.JWTMiddleware(suite.Config.JWTPublicKey))
	suite.poamHandler.Register(poamGroup)

	// Register evidence handler
	evidenceGroup := apiGroup.Group("/evidence")
	evidenceGroup.Use(middleware.JWTMiddleware(suite.Config.JWTPublicKey))
	suite.evidenceHandler.Register(evidenceGroup)
}

func (suite *InventoryApiIntegrationSuite) SetupTest() {
	// Use proper database refresh to ensure test isolation and recreate test user
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

// Helper function to create authenticated requests
func (suite *InventoryApiIntegrationSuite) createRequest(method, path string, body any) *http.Request {
	var bodyReader *bytes.Buffer
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		bodyReader = bytes.NewBuffer(bodyBytes)
	} else {
		bodyReader = bytes.NewBuffer([]byte{})
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	token, _ := suite.GetAuthToken()
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	return req
}

// Helper function to create a test SSP with inventory items
func (suite *InventoryApiIntegrationSuite) createSSPWithInventory() (*oscalTypes_1_1_3.SystemSecurityPlan, []oscalTypes_1_1_3.InventoryItem) {
	sspUUID := uuid.New().String()
	now := time.Now()

	inventoryItems := []oscalTypes_1_1_3.InventoryItem{
		{
			UUID:        uuid.New().String(),
			Description: "Web Server",
			Props: &[]oscalTypes_1_1_3.Property{
				{Name: "asset-id", Value: "web-01"},
				{Name: "asset-type", Value: "web-server"},
			},
		},
		{
			UUID:        uuid.New().String(),
			Description: "Database Server",
			Props: &[]oscalTypes_1_1_3.Property{
				{Name: "asset-id", Value: "db-01"},
				{Name: "asset-type", Value: "database"},
			},
		},
	}

	ssp := &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspUUID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Test SSP with Inventory",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{
			Href: "https://example.com/profiles/test",
		},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName:               "Test System",
			Description:              "A test system with inventory",
			SecuritySensitivityLevel: "moderate",
			SystemIds: []oscalTypes_1_1_3.SystemId{
				{
					IdentifierType: "https://ietf.org/rfc/rfc4122",
					ID:             uuid.New().String(),
				},
			},
			Status: oscalTypes_1_1_3.Status{
				State: "operational",
			},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Users: []oscalTypes_1_1_3.SystemUser{
				{
					UUID:  uuid.New().String(),
					Title: "Test User",
				},
			},
			Components: []oscalTypes_1_1_3.SystemComponent{
				{
					UUID:  uuid.New().String(),
					Title: "Test Component",
					Type:  "software",
				},
			},
			InventoryItems: &inventoryItems,
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "Test control implementation",
		},
	}

	return ssp, inventoryItems
}

// Helper function to create evidence with inventory items
func (suite *InventoryApiIntegrationSuite) createEvidenceWithInventory() (*handler.EvidenceCreateRequest, []handler.EvidenceInventoryItem) {
	inventoryItems := []handler.EvidenceInventoryItem{
		{
			Identifier:  "operating-system/ubuntu/22.04",
			Type:        "operating-system",
			Title:       "Ubuntu Server",
			Description: "Ubuntu 22.04 LTS Server",
			Props: []oscalTypes_1_1_3.Property{
				{Name: "asset-type", Value: "operating-system"},
				{Name: "version", Value: "22.04"},
			},
		},
		{
			Identifier:  "firewall/pf/1.0",
			Type:        "firewall",
			Title:       "PF Firewall",
			Description: "Packet Filter firewall",
			Props: []oscalTypes_1_1_3.Property{
				{Name: "asset-type", Value: "firewall"},
			},
		},
	}

	evidence := &handler.EvidenceCreateRequest{
		UUID:           uuid.New(),
		Title:          "Test Evidence with Inventory",
		Description:    "Evidence containing inventory items from agent scan",
		Start:          time.Now().Add(-1 * time.Hour),
		End:            time.Now(),
		InventoryItems: inventoryItems,
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: "satisfied",
		},
	}

	return evidence, inventoryItems
}

// Helper function to create a POAM with inventory items
func (suite *InventoryApiIntegrationSuite) createPOAMWithInventory() (*oscalTypes_1_1_3.PlanOfActionAndMilestones, []oscalTypes_1_1_3.InventoryItem) {
	poamUUID := uuid.New().String()
	now := time.Now()

	inventoryItems := []oscalTypes_1_1_3.InventoryItem{
		{
			UUID:        uuid.New().String(),
			Description: "Legacy System",
			Props: &[]oscalTypes_1_1_3.Property{
				{Name: "asset-id", Value: "legacy-01"},
				{Name: "asset-type", Value: "appliance"},
			},
		},
	}

	poam := &oscalTypes_1_1_3.PlanOfActionAndMilestones{
		UUID: poamUUID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Test POAM with Inventory",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
		},
		ImportSsp: &oscalTypes_1_1_3.ImportSsp{
			Href: "https://example.com/ssp/test",
		},
		SystemId: &oscalTypes_1_1_3.SystemId{
			IdentifierType: "https://ietf.org/rfc/rfc4122",
			ID:             uuid.New().String(),
		},
		LocalDefinitions: &oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions{
			InventoryItems: &inventoryItems,
		},
		PoamItems: []oscalTypes_1_1_3.PoamItem{
			{
				UUID:        uuid.New().String(),
				Title:       "Test POAM Item",
				Description: "A test POAM item",
			},
		},
	}

	return poam, inventoryItems
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_Empty() {
	// Test when database is empty
	req := suite.createRequest(http.MethodGet, "/api/oscal/inventory", nil)
	rec := httptest.NewRecorder()

	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)
	suite.Empty(response.Data)
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_FromSSP() {
	// Create an SSP with inventory items
	ssp, expectedItems := suite.createSSPWithInventory()

	// Save SSP to database
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Get all inventory items
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)
	suite.Len(response.Data, len(expectedItems))

	// Verify items are from SSP
	for _, item := range response.Data {
		suite.Equal("System Security Plan", item.Source)
		suite.Equal("ssp", item.SourceType)
		suite.NotEmpty(item.UUID)
	}
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_FromEvidence() {
	// Create evidence with inventory items
	evidence, expectedItems := suite.createEvidenceWithInventory()

	// Save evidence to database
	req := suite.createRequest(http.MethodPost, "/api/evidence", evidence)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Get all inventory items
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory?include_evidence=true&include_ssp=false", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)
	suite.Len(response.Data, len(expectedItems))

	// Verify items are from Evidence
	for _, item := range response.Data {
		suite.Equal("Evidence Collection", item.Source)
		suite.Equal("evidence", item.SourceType)
	}
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_FromPOAM() {
	// Create a POAM with inventory items
	poam, expectedItems := suite.createPOAMWithInventory()

	// Save POAM to database
	req := suite.createRequest(http.MethodPost, "/api/oscal/plan-of-action-and-milestones", poam)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Get all inventory items from POAM only
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory?include_poam=true&include_ssp=false&include_evidence=false", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)
	suite.Len(response.Data, len(expectedItems))

	// Verify items are from POAM
	for _, item := range response.Data {
		suite.Equal("Plan of Action and Milestones", item.Source)
		suite.Equal("poam", item.SourceType)
	}
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_WithTypeFilter() {
	// Create SSP with different types of inventory
	ssp, _ := suite.createSSPWithInventory()

	// Save SSP
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Filter by web-server type
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory?item_type=web-server", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)
	suite.Len(response.Data, 1)
	suite.Equal("Web Server", response.Data[0].Description)
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_WithSSPAttachmentFilter() {
	// Create SSP with inventory
	ssp, _ := suite.createSSPWithInventory()
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Create evidence with inventory (not attached to SSP)
	evidence, _ := suite.createEvidenceWithInventory()
	req = suite.createRequest(http.MethodPost, "/api/evidence", evidence)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Get only items attached to SSP
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory?attached_to_ssp=true", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)

	// Should only get SSP items
	for _, item := range response.Data {
		suite.Equal("ssp", item.SourceType)
	}

	// Get only items NOT attached to SSP
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory?attached_to_ssp=false", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	err = json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)

	// Should only get evidence items
	for _, item := range response.Data {
		suite.Equal("evidence", item.SourceType)
	}
}

func (suite *InventoryApiIntegrationSuite) TestGetInventoryItem() {
	// Create and save SSP with inventory
	ssp, _ := suite.createSSPWithInventory()
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// First get all inventory items to get the actual saved UUIDs
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var listResponse handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&listResponse)
	suite.NoError(err)
	suite.NotEmpty(listResponse.Data, "Should have inventory items")

	// Get the first item by its actual saved ID
	itemID := listResponse.Data[0].UUID
	req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/inventory/%s", itemID), nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataResponse[InventoryItemWithSource]
	err = json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal(itemID, response.Data.UUID)
	suite.Equal("System Security Plan", response.Data.Source)
	suite.Equal("ssp", response.Data.SourceType)
}

func (suite *InventoryApiIntegrationSuite) TestGetInventoryItem_NotFound() {
	// Try to get non-existent item
	fakeID := uuid.New().String()
	req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/inventory/%s", fakeID), nil)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusNotFound, rec.Code)
}

func (suite *InventoryApiIntegrationSuite) TestGetInventoryItem_InvalidUUID() {
	// Try to get item with invalid UUID
	req := suite.createRequest(http.MethodGet, "/api/oscal/inventory/invalid-uuid", nil)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_Unauthorized() {
	// Create request without auth token
	req := httptest.NewRequest(http.MethodGet, "/api/oscal/inventory", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusUnauthorized, rec.Code)
}

func (suite *InventoryApiIntegrationSuite) TestGetAllInventoryItems_MultipleSourcesFilter() {
	// Create SSP with inventory
	ssp, _ := suite.createSSPWithInventory()
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Create POAM with inventory
	poam, _ := suite.createPOAMWithInventory()
	req = suite.createRequest(http.MethodPost, "/api/oscal/plan-of-action-and-milestones", poam)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Get items from SSP and POAM only
	req = suite.createRequest(http.MethodGet, "/api/oscal/inventory?include_ssp=true&include_poam=true&include_evidence=false", nil)
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataListResponse[InventoryItemWithSource]
	err := json.NewDecoder(rec.Body).Decode(&response)
	suite.NoError(err)
	suite.Len(response.Data, 3) // 2 from SSP + 1 from POAM

	// Verify sources
	sourceTypes := make(map[string]bool)
	for _, item := range response.Data {
		sourceTypes[item.SourceType] = true
	}
	suite.True(sourceTypes["ssp"])
	suite.True(sourceTypes["poam"])
	suite.False(sourceTypes["evidence"])
}

// TestInventoryApiIntegration runs the integration test suite
func TestInventoryApiIntegration(t *testing.T) {
	suite.Run(t, new(InventoryApiIntegrationSuite))
}
