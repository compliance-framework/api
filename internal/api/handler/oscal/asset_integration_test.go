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

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestAssetApi(t *testing.T) {
	suite.Run(t, new(AssetApiIntegrationSuite))
}

type AssetApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *AssetApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config)
}

func (suite *AssetApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

// Helper method to create a test request with Bearer token authentication
func (suite *AssetApiIntegrationSuite) createRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		suite.Require().NoError(err, "Failed to marshal request body")
	}

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))

	return rec, req
}

// Helper method to create a test assessment plan (prerequisite for asset tests)
func (suite *AssetApiIntegrationSuite) createTestAssessmentPlan() uuid.UUID {
	planID := uuid.New()
	testPlan := &oscalTypes_1_1_3.AssessmentPlan{
		UUID: planID.String(),
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:   "Test Assessment Plan for Assets",
			Version: "1.0.0",
		},
		ImportSsp: oscalTypes_1_1_3.ImportSsp{
			Href: "test-ssp-reference",
		},
	}

	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/assessment-plans", testPlan)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, "Failed to create test assessment plan")

	return planID
}

// Helper method to create test assessment asset data
func (suite *AssetApiIntegrationSuite) createTestAssessmentAssetData() *oscalTypes_1_1_3.AssessmentAssets {
	platformID := uuid.New()
	componentID := uuid.New()

	return &oscalTypes_1_1_3.AssessmentAssets{
		AssessmentPlatforms: []oscalTypes_1_1_3.AssessmentPlatform{
			{
				UUID:  platformID.String(),
				Title: "Test Assessment Platform",
				Props: &[]oscalTypes_1_1_3.Property{
					{
						Name:  "platform-type",
						Value: "automated",
					},
				},
			},
		},
		Components: &[]oscalTypes_1_1_3.SystemComponent{
			{
				UUID:        componentID.String(),
				Title:       "Test Assessment Component",
				Description: "Test assessment component for integration testing",
				Type:        "software",
				Status: oscalTypes_1_1_3.SystemComponentStatus{
					State: "operational",
				},
			},
		},
	}
}

func (suite *AssetApiIntegrationSuite) TestCreateAssessmentAsset() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testAsset := suite.createTestAssessmentAssetData()

	// Create assessment asset
	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), testAsset)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Verify response
	var response handler.GenericDataResponse[struct {
		*oscalTypes_1_1_3.AssessmentAssets
		ID string `json:"id"`
	}]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Require().Len(response.Data.AssessmentPlatforms, 1)
	suite.Equal(testAsset.AssessmentPlatforms[0].UUID, response.Data.AssessmentPlatforms[0].UUID)
	suite.Equal(testAsset.AssessmentPlatforms[0].Title, response.Data.AssessmentPlatforms[0].Title)
	if response.Data.Components != nil && len(*response.Data.Components) > 0 {
		suite.Equal((*testAsset.Components)[0].UUID, (*response.Data.Components)[0].UUID)
		suite.Equal((*testAsset.Components)[0].Title, (*response.Data.Components)[0].Title)
		suite.Equal((*testAsset.Components)[0].Description, (*response.Data.Components)[0].Description)
	}
}

func (suite *AssetApiIntegrationSuite) TestGetAssessmentAssets() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testAsset := suite.createTestAssessmentAssetData()

	// Create assessment asset first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), testAsset)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Get assessment assets
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	// Verify response
	var response handler.GenericDataResponse[[]*oscalTypes_1_1_3.AssessmentAssets]
	err := json.Unmarshal(getRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Require().Len(response.Data, 1)
	suite.Require().Len(response.Data[0].AssessmentPlatforms, 1)
	suite.Equal(testAsset.AssessmentPlatforms[0].UUID, response.Data[0].AssessmentPlatforms[0].UUID)
	suite.Equal(testAsset.AssessmentPlatforms[0].Title, response.Data[0].AssessmentPlatforms[0].Title)
}

func (suite *AssetApiIntegrationSuite) TestUpdateAssessmentAsset() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testAsset := suite.createTestAssessmentAssetData()

	// Create assessment asset first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), testAsset)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Extract the database ID from create response
	var createResponse handler.GenericDataResponse[struct {
		*oscalTypes_1_1_3.AssessmentAssets
		ID string `json:"id"`
	}]
	err := json.Unmarshal(createRec.Body.Bytes(), &createResponse)
	suite.Require().NoError(err)
	assetID := createResponse.Data.ID

	// Update assessment asset
	testAsset.AssessmentPlatforms[0].Title = "Updated Test Assessment Platform"
	if testAsset.Components != nil && len(*testAsset.Components) > 0 {
		(*testAsset.Components)[0].Description = "Updated test assessment component description"
	}

	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets/%s", planID, assetID), testAsset)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusOK, updateRec.Code)

	// Verify response
	var response handler.GenericDataResponse[struct {
		*oscalTypes_1_1_3.AssessmentAssets
		ID string `json:"id"`
	}]
	err = json.Unmarshal(updateRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Require().Len(response.Data.AssessmentPlatforms, 1)
	suite.Equal(testAsset.AssessmentPlatforms[0].UUID, response.Data.AssessmentPlatforms[0].UUID)
	suite.Equal("Updated Test Assessment Platform", response.Data.AssessmentPlatforms[0].Title)
	if response.Data.Components != nil && len(*response.Data.Components) > 0 {
		suite.Equal("Updated test assessment component description", (*response.Data.Components)[0].Description)
	}
}

func (suite *AssetApiIntegrationSuite) TestDeleteAssessmentAsset() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testAsset := suite.createTestAssessmentAssetData()

	// Create assessment asset first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), testAsset)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Extract the database ID from create response
	var createResponse handler.GenericDataResponse[struct {
		*oscalTypes_1_1_3.AssessmentAssets
		ID string `json:"id"`
	}]
	err := json.Unmarshal(createRec.Body.Bytes(), &createResponse)
	suite.Require().NoError(err)
	assetID := createResponse.Data.ID

	// Delete assessment asset
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets/%s", planID, assetID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusNoContent, deleteRec.Code)

	// Verify assessment asset is deleted by trying to get assessment assets
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	var response handler.GenericDataResponse[[]*oscalTypes_1_1_3.AssessmentAssets]
	err = json.Unmarshal(getRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 0)
}

func (suite *AssetApiIntegrationSuite) TestAssessmentAssetValidationErrors() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()

	// Test with invalid assessment asset (missing required fields)
	invalidAsset := &oscalTypes_1_1_3.AssessmentAssets{
		// Missing AssessmentPlatforms which is required
		AssessmentPlatforms: []oscalTypes_1_1_3.AssessmentPlatform{},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), invalidAsset)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *AssetApiIntegrationSuite) TestAssessmentAssetNotFound() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	nonExistentAssetID := uuid.New()

	// Try to update non-existent assessment asset
	testAsset := suite.createTestAssessmentAssetData()
	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets/%s", planID, nonExistentAssetID), testAsset)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusNotFound, updateRec.Code)

	// Try to delete non-existent assessment asset
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets/%s", planID, nonExistentAssetID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusNotFound, deleteRec.Code)
}

func (suite *AssetApiIntegrationSuite) TestAssessmentPlanNotFound() {
	nonExistentPlanID := uuid.New()
	testAsset := suite.createTestAssessmentAssetData()

	// Try to create assessment asset for non-existent assessment plan
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", nonExistentPlanID), testAsset)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusNotFound, createRec.Code)

	// Try to get assessment assets for non-existent assessment plan
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", nonExistentPlanID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusNotFound, getRec.Code)
}

func (suite *AssetApiIntegrationSuite) TestAssessmentAssetInvalidUUIDs() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testAsset := suite.createTestAssessmentAssetData()

	// Test with invalid assessment plan UUID
	invalidRec, invalidReq := suite.createRequest(http.MethodPost, "/api/oscal/assessment-plans/invalid-uuid/assessment-assets", testAsset)
	suite.server.E().ServeHTTP(invalidRec, invalidReq)
	suite.Equal(http.StatusBadRequest, invalidRec.Code)

	// Create a valid assessment asset first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets", planID), testAsset)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Test with invalid assessment asset UUID for update
	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets/invalid-uuid", planID), testAsset)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusBadRequest, updateRec.Code)

	// Test with invalid assessment asset UUID for delete
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-assets/invalid-uuid", planID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusBadRequest, deleteRec.Code)
}
