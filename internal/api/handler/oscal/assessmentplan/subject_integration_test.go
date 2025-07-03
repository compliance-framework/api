//go:build integration

package assessmentplan

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

func TestSubjectApi(t *testing.T) {
	suite.Run(t, new(SubjectApiIntegrationSuite))
}

type SubjectApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *SubjectApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config)
}

func (suite *SubjectApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

// Helper method to create a test request with Bearer token authentication
func (suite *SubjectApiIntegrationSuite) createRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

// Helper method to create a test assessment plan (prerequisite for subject tests)
func (suite *SubjectApiIntegrationSuite) createTestAssessmentPlan() uuid.UUID {
	planID := uuid.New()
	testPlan := &oscalTypes_1_1_3.AssessmentPlan{
		UUID: planID.String(),
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:   "Test Assessment Plan for Subjects",
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

// Helper method to create test assessment subject data
func (suite *SubjectApiIntegrationSuite) createTestAssessmentSubjectData() *oscalTypes_1_1_3.AssessmentSubject {
	subjectID := uuid.New()
	return &oscalTypes_1_1_3.AssessmentSubject{
		UUID:        subjectID.String(),
		Title:       "Test Assessment Subject",
		Description: "Test assessment subject description for integration testing",
		Type:        "component",
	}
}

func (suite *SubjectApiIntegrationSuite) TestCreateAssessmentSubject() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testSubject := suite.createTestAssessmentSubjectData()

	// Create assessment subject
	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), testSubject)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Verify response
	var response handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentSubject]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Equal(testSubject.UUID, response.Data.UUID)
	suite.Equal(testSubject.Title, response.Data.Title)
	suite.Equal(testSubject.Description, response.Data.Description)
	suite.Equal(testSubject.Type, response.Data.Type)
}

func (suite *SubjectApiIntegrationSuite) TestGetAssessmentSubjects() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testSubject := suite.createTestAssessmentSubjectData()

	// Create assessment subject first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), testSubject)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Get assessment subjects
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	// Verify response
	var response handler.GenericDataResponse[[]*oscalTypes_1_1_3.AssessmentSubject]
	err := json.Unmarshal(getRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Require().Len(response.Data, 1)
	suite.Equal(testSubject.UUID, response.Data[0].UUID)
	suite.Equal(testSubject.Title, response.Data[0].Title)
	suite.Equal(testSubject.Type, response.Data[0].Type)
}

func (suite *SubjectApiIntegrationSuite) TestUpdateAssessmentSubject() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testSubject := suite.createTestAssessmentSubjectData()

	// Create assessment subject first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), testSubject)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Update assessment subject
	testSubject.Title = "Updated Test Assessment Subject"
	testSubject.Description = "Updated test assessment subject description"
	testSubject.Type = "inventory-item"

	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects/%s", planID, testSubject.UUID), testSubject)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusOK, updateRec.Code)

	// Verify response
	var response handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentSubject]
	err := json.Unmarshal(updateRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Equal(testSubject.UUID, response.Data.UUID)
	suite.Equal("Updated Test Assessment Subject", response.Data.Title)
	suite.Equal("Updated test assessment subject description", response.Data.Description)
	suite.Equal("inventory-item", response.Data.Type)
}

func (suite *SubjectApiIntegrationSuite) TestDeleteAssessmentSubject() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testSubject := suite.createTestAssessmentSubjectData()

	// Create assessment subject first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), testSubject)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Delete assessment subject
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects/%s", planID, testSubject.UUID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusNoContent, deleteRec.Code)

	// Verify assessment subject is deleted by trying to get assessment subjects
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	var response handler.GenericDataResponse[[]*oscalTypes_1_1_3.AssessmentSubject]
	err := json.Unmarshal(getRec.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 0)
}

func (suite *SubjectApiIntegrationSuite) TestAssessmentSubjectValidationErrors() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()

	// Test with invalid assessment subject (missing required fields)
	invalidSubject := &oscalTypes_1_1_3.AssessmentSubject{
		UUID: "invalid-uuid",
		// Missing Title and Type which are required
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), invalidSubject)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *SubjectApiIntegrationSuite) TestAssessmentSubjectNotFound() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	nonExistentSubjectID := uuid.New()

	// Try to update non-existent assessment subject
	testSubject := suite.createTestAssessmentSubjectData()
	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects/%s", planID, nonExistentSubjectID), testSubject)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusNotFound, updateRec.Code)

	// Try to delete non-existent assessment subject
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects/%s", planID, nonExistentSubjectID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusNotFound, deleteRec.Code)
}

func (suite *SubjectApiIntegrationSuite) TestAssessmentPlanNotFound() {
	nonExistentPlanID := uuid.New()
	testSubject := suite.createTestAssessmentSubjectData()

	// Try to create assessment subject for non-existent assessment plan
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", nonExistentPlanID), testSubject)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusNotFound, createRec.Code)

	// Try to get assessment subjects for non-existent assessment plan
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", nonExistentPlanID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusNotFound, getRec.Code)
}

func (suite *SubjectApiIntegrationSuite) TestAssessmentSubjectInvalidUUIDs() {
	// Create test assessment plan first
	planID := suite.createTestAssessmentPlan()
	testSubject := suite.createTestAssessmentSubjectData()

	// Test with invalid assessment plan UUID
	invalidRec, invalidReq := suite.createRequest(http.MethodPost, "/api/oscal/assessment-plans/invalid-uuid/assessment-subjects", testSubject)
	suite.server.E().ServeHTTP(invalidRec, invalidReq)
	suite.Equal(http.StatusBadRequest, invalidRec.Code)

	// Create a valid assessment subject first
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects", planID), testSubject)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Require().Equal(http.StatusCreated, createRec.Code)

	// Test with invalid assessment subject UUID for update
	updateRec, updateReq := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects/invalid-uuid", planID), testSubject)
	suite.server.E().ServeHTTP(updateRec, updateReq)
	suite.Equal(http.StatusBadRequest, updateRec.Code)

	// Test with invalid assessment subject UUID for delete
	deleteRec, deleteReq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-plans/%s/assessment-subjects/invalid-uuid", planID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	suite.Equal(http.StatusBadRequest, deleteRec.Code)
}
