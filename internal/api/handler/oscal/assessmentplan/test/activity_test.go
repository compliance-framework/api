//go:build integration

package test

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

func TestActivityApi(t *testing.T) {
	suite.Run(t, new(ActivityApiIntegrationSuite))
}

type ActivityApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *ActivityApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config)
}

func (suite *ActivityApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

// Helper method to create a test request with Bearer token authentication
func (suite *ActivityApiIntegrationSuite) createRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

// Helper method to create a test assessment plan (prerequisite for activity tests)
func (suite *ActivityApiIntegrationSuite) createTestAssessmentPlan() uuid.UUID {
	planID := uuid.New()
	testPlan := &oscalTypes_1_1_3.AssessmentPlan{
		UUID: planID.String(),
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:   "Test Assessment Plan for Activities",
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

// Helper method to create test activity data
func (suite *ActivityApiIntegrationSuite) createTestActivityData() *oscalTypes_1_1_3.Activity {
	activityID := uuid.New()
	return &oscalTypes_1_1_3.Activity{
		UUID:        activityID.String(),
		Title:       "Test Activity",
		Description: "Test activity description for integration testing",
	}
}

func (suite *ActivityApiIntegrationSuite) TestCreateActivity() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testActivity := suite.createTestActivityData()

	// Create activity
	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), testActivity)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Verify response
	var response handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Equal(testActivity.UUID, response.Data.UUID)
	suite.Equal(testActivity.Title, response.Data.Title)
	suite.Equal(testActivity.Description, response.Data.Description)
}

func (suite *ActivityApiIntegrationSuite) TestGetActivities() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testActivity := suite.createTestActivityData()

	// Create activity first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), testActivity)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Get activities
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	// Verify response
	var response handler.GenericDataResponse[[]*oscalTypes_1_1_3.Activity]
	err := json.Unmarshal(getRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Require().Len(response.Data, 1)
	suite.Equal(testActivity.UUID, response.Data[0].UUID)
	suite.Equal(testActivity.Title, response.Data[0].Title)
}

func (suite *ActivityApiIntegrationSuite) TestUpdateActivity() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testActivity := suite.createTestActivityData()

	// Create activity first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), testActivity)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Update activity
	testActivity.Title = "Updated Test Activity"
	testActivity.Description = "Updated test activity description"

	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities/%s", planID, testActivity.UUID), testActivity)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusOK, updateRec.Code)

	// Verify response
	var response handler.GenericDataResponse[*oscalTypes_1_1_3.Activity]
	err := json.Unmarshal(updateRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Equal(testActivity.UUID, response.Data.UUID)
	suite.Equal("Updated Test Activity", response.Data.Title)
	suite.Equal("Updated test activity description", response.Data.Description)
}

func (suite *ActivityApiIntegrationSuite) TestDeleteActivity() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testActivity := suite.createTestActivityData()

	// Create activity first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), testActivity)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Delete activity
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities/%s", planID, testActivity.UUID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusNoContent, deleteRec.Code)

	// Verify activity is deleted by trying to get activities
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	var response handler.GenericDataResponse[[]*oscalTypes_1_1_3.Activity]
	err := json.Unmarshal(getRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 0)
}

func (suite *ActivityApiIntegrationSuite) TestActivityValidationErrors() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()

	// Test with invalid activity (missing required fields)
	invalidActivity := &oscalTypes_1_1_3.Activity{
		UUID: "invalid-uuid",
		// Missing Title which is required
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), invalidActivity)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *ActivityApiIntegrationSuite) TestActivityNotFound() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	nonExistentActivityID := uuid.New()

	// Try to update non-existent activity
	testActivity := suite.createTestActivityData()
	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities/%s", planID, nonExistentActivityID), testActivity)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusNotFound, updateRec.Code)

	// Try to delete non-existent activity
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities/%s", planID, nonExistentActivityID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusNotFound, deleteRec.Code)
}

func (suite *ActivityApiIntegrationSuite) TestAssessmentPlanNotFound() {
	nonExistentPlanID := uuid.New()
	testActivity := suite.createTestActivityData()

	// Try to create activity for non-existent assessment plan
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", nonExistentPlanID), testActivity)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusNotFound, createRec.Code)

	// Try to get activities for non-existent assessment plan
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", nonExistentPlanID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusNotFound, getRec.Code)
}

func (suite *ActivityApiIntegrationSuite) TestActivityInvalidUUIDs() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testActivity := suite.createTestActivityData()

	// Test with invalid assessment plan UUID
	invalidRec, invalidReq := suite.createRequest(http.MethodPost, "/api/oscal/assessment-plans/invalid-uuid/activities", testActivity)
	suite.server.E().ServeHTTP(invalidRec, invalidReq)
	suite.Equal(http.StatusBadRequest, invalidRec.Code)

	// Create a valid activity first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities", planID), testActivity)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Test with invalid activity UUID for update
	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities/invalid-uuid", planID), testActivity)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusBadRequest, updateRec.Code)

	// Test with invalid activity UUID for delete
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/activities/invalid-uuid", planID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusBadRequest, deleteRec.Code)
}
