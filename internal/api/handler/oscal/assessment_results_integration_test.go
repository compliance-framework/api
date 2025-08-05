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

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestAssessmentResultsApi(t *testing.T) {
	suite.Run(t, new(AssessmentResultsApiIntegrationSuite))
}

type AssessmentResultsApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *AssessmentResultsApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()
	suite.logger = logger.Sugar()
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config)
}

func (suite *AssessmentResultsApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

// Helper method to create a test request with Bearer token authentication
func (suite *AssessmentResultsApiIntegrationSuite) createRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

// Helper function to create a basic Assessment Results and return its UUID
func (suite *AssessmentResultsApiIntegrationSuite) createBasicAssessmentResults() string {
	arUUID := uuid.New().String()

	createAR := oscaltypes.AssessmentResults{
		UUID: arUUID,
		Metadata: oscaltypes.Metadata{
			Title:   "Test Assessment Results",
			Version: "1.0.0",
		},
		ImportAp: oscaltypes.ImportAp{
			Href: "https://example.com/assessment-plan.json",
		},
		Results: []oscaltypes.Result{
			{
				UUID:        uuid.New().String(),
				Title:       "Test Result",
				Description: "Test result description",
				Start:       time.Now(),
				ReviewedControls: oscaltypes.ReviewedControls{
					Description: "Controls reviewed",
				},
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/assessment-results", createAR)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	return arUUID
}

// Test Create endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateAssessmentResults() {
	testAR := oscaltypes.AssessmentResults{
		UUID: uuid.New().String(),
		Metadata: oscaltypes.Metadata{
			Title:   "Test Assessment Results",
			Version: "1.0.0",
		},
		ImportAp: oscaltypes.ImportAp{
			Href: "https://example.com/assessment-plan.json",
		},
		Results: []oscaltypes.Result{
			{
				UUID:        uuid.New().String(),
				Title:       "Test Result",
				Description: "Test result description",
				Start:       time.Now(),
				ReviewedControls: oscaltypes.ReviewedControls{
					Description: "Controls reviewed",
				},
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/assessment-results", testAR)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusCreated, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(testAR.UUID, response.Data.UUID)
	suite.Equal(testAR.Metadata.Title, response.Data.Metadata.Title)
}

// Test Get endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetAssessmentResults() {
	arUUID := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(arUUID, response.Data.UUID)
}

// Test List endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestListAssessmentResults() {
	// Create multiple assessment results
	arUUID1 := suite.createBasicAssessmentResults()
	arUUID2 := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodGet, "/api/oscal/assessment-results", nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataListResponse[oscaltypes.AssessmentResults]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.GreaterOrEqual(len(response.Data), 2)

	// Verify our created items are in the list
	uuids := make(map[string]bool)
	for _, ar := range response.Data {
		uuids[ar.UUID] = true
	}
	suite.True(uuids[arUUID1])
	suite.True(uuids[arUUID2])
}

// Test Update endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateAssessmentResults() {
	arUUID := suite.createBasicAssessmentResults()

	// Get the full assessment results (including Results)
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/full", arUUID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	var getResponse handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err := json.Unmarshal(getRec.Body.Bytes(), &getResponse)
	suite.NoError(err)

	// Update the assessment results
	updatedAR := getResponse.Data
	updatedAR.Metadata.Title = "Updated Assessment Results"
	updatedAR.Metadata.Version = "2.0.0"

	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s", arUUID), updatedAR)
	suite.server.E().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		suite.T().Logf("Update response: %d, body: %s", rec.Code, rec.Body.String())
	}
	suite.Equal(http.StatusOK, rec.Code)

	var response handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal("Updated Assessment Results", response.Data.Metadata.Title)
	suite.Equal("2.0.0", response.Data.Metadata.Version)
}

// Test Get Full endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetFullAssessmentResults() {
	arUUID := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/full", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(arUUID, response.Data.UUID)
	suite.Len(response.Data.Results, 1)
}

// Test Delete endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestDeleteAssessmentResults() {
	arUUID := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusNoContent, rec.Code)

	// Verify deletion
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s", arUUID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusNotFound, getRec.Code)
}

// Test Get Metadata endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetAssessmentResultsMetadata() {
	arUUID := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/metadata", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.Metadata]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal("Test Assessment Results", response.Data.Title)
}

// Test Update Metadata endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateAssessmentResultsMetadata() {
	arUUID := suite.createBasicAssessmentResults()

	metadata := oscaltypes.Metadata{
		Title:   "New Metadata Title",
		Version: "2.0.0",
	}
	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/metadata", arUUID), metadata)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.Metadata]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal("New Metadata Title", response.Data.Title)
	suite.Equal("2.0.0", response.Data.Version)
}

// Test Get Import AP endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetAssessmentResultsImportAp() {
	arUUID := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/import-ap", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.ImportAp]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal("https://example.com/assessment-plan.json", response.Data.Href)
}

// Test Update Import AP endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateAssessmentResultsImportAp() {
	arUUID := suite.createBasicAssessmentResults()

	importAp := oscaltypes.ImportAp{
		Href:    "https://example.com/new-assessment-plan.json",
		Remarks: "Updated assessment plan reference",
	}
	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/import-ap", arUUID), importAp)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.ImportAp]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(importAp.Href, response.Data.Href)
	suite.Equal(importAp.Remarks, response.Data.Remarks)
}

// Test Create Result endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateResult() {
	arUUID := suite.createBasicAssessmentResults()

	testResult := oscaltypes.Result{
		UUID:        uuid.New().String(),
		Title:       "Test Result",
		Description: "Test result description",
		Start:       time.Now(),
		ReviewedControls: oscaltypes.ReviewedControls{
			Description: "Controls reviewed",
		},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results", arUUID), testResult)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusCreated, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.Result]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(testResult.UUID, response.Data.UUID)
}

// Test Get Results endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetResults() {
	arUUID := suite.createBasicAssessmentResults()

	// Add an additional result
	testResult := oscaltypes.Result{
		UUID:        uuid.New().String(),
		Title:       "Additional Result",
		Description: "Additional result description",
		Start:       time.Now(),
		ReviewedControls: oscaltypes.ReviewedControls{
			Description: "Additional controls reviewed",
		},
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results", arUUID), testResult)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataListResponse[oscaltypes.Result]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Len(response.Data, 2) // One from creation + one we just added
}

// Test Get single Result endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetResult() {
	arUUID := suite.createBasicAssessmentResults()

	// Create a result to get
	testResult := oscaltypes.Result{
		UUID:        uuid.New().String(),
		Title:       "Test Result",
		Description: "Test result description",
		Start:       time.Now(),
		ReviewedControls: oscaltypes.ReviewedControls{
			Description: "Controls reviewed",
		},
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results", arUUID), testResult)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s", arUUID, testResult.UUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.Result]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(testResult.UUID, response.Data.UUID)
}

// Test Update Result endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateResult() {
	arUUID := suite.createBasicAssessmentResults()

	// Create a result to update
	testResult := oscaltypes.Result{
		UUID:        uuid.New().String(),
		Title:       "Test Result",
		Description: "Test result description",
		Start:       time.Now(),
		ReviewedControls: oscaltypes.ReviewedControls{
			Description: "Controls reviewed",
		},
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results", arUUID), testResult)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	// Update the result
	testResult.Title = "Updated Result"
	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s", arUUID, testResult.UUID), testResult)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.Result]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal("Updated Result", response.Data.Title)
}

// Test Delete Result endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestDeleteResult() {
	arUUID := suite.createBasicAssessmentResults()

	// Create a result to delete
	testResult := oscaltypes.Result{
		UUID:        uuid.New().String(),
		Title:       "Test Result",
		Description: "Test result description",
		Start:       time.Now(),
		ReviewedControls: oscaltypes.ReviewedControls{
			Description: "Controls reviewed",
		},
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results", arUUID), testResult)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	rec, req := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s", arUUID, testResult.UUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusNoContent, rec.Code)

	// Verify deletion
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s", arUUID, testResult.UUID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusNotFound, getRec.Code)
}

// Test Create with invalid UUID
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateAssessmentResultsWithInvalidUUID() {
	invalidAR := oscaltypes.AssessmentResults{
		UUID: "invalid-uuid",
		Metadata: oscaltypes.Metadata{
			Title:   "Test",
			Version: "1.0.0",
		},
		ImportAp: oscaltypes.ImportAp{
			Href: "https://example.com/ap.json",
		},
		Results: []oscaltypes.Result{},
	}
	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/assessment-results", invalidAR)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusBadRequest, rec.Code)
}

// Test Create without required fields
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateAssessmentResultsWithoutRequiredFields() {
	invalidAR := oscaltypes.AssessmentResults{
		UUID: uuid.New().String(),
		// Missing metadata
	}
	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/assessment-results", invalidAR)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusBadRequest, rec.Code)
}

// Test Get non-existent assessment results
func (suite *AssessmentResultsApiIntegrationSuite) TestGetNonExistentAssessmentResults() {
	nonExistentID := uuid.New().String()
	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s", nonExistentID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusNotFound, rec.Code)
}

// Test Update non-existent assessment results
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateNonExistentAssessmentResults() {
	nonExistentID := uuid.New().String()
	ar := oscaltypes.AssessmentResults{
		UUID: nonExistentID,
		Metadata: oscaltypes.Metadata{
			Title:   "Test",
			Version: "1.0.0",
		},
		ImportAp: oscaltypes.ImportAp{
			Href: "https://example.com/ap.json",
		},
		Results: []oscaltypes.Result{
			{
				UUID:        uuid.New().String(),
				Title:       "Test Result",
				Description: "Test result description",
				Start:       time.Now(),
				ReviewedControls: oscaltypes.ReviewedControls{
					Description: "Controls reviewed",
				},
			},
		},
	}
	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s", nonExistentID), ar)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusNotFound, rec.Code)
}

// Test Back Matter endpoints

// Test Get Back Matter endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetBackMatter() {
	arUUID := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.BackMatter]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.NotNil(response.Data.Resources)
	suite.Len(*response.Data.Resources, 0) // Should be empty initially
}

// Test Create Back Matter endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateBackMatter() {
	arUUID := suite.createBasicAssessmentResults()

	backMatter := oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				UUID:        uuid.New().String(),
				Title:       "Test Resource",
				Description: "Test resource description",
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), backMatter)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusCreated, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.BackMatter]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.NotNil(response.Data.Resources)
	suite.Len(*response.Data.Resources, 1)
}

// Test Create Back Matter with invalid resource UUID
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateBackMatterWithInvalidResourceUUID() {
	arUUID := suite.createBasicAssessmentResults()

	// Test with missing UUID
	backMatter := oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				Title:       "Test Resource",
				Description: "Test resource description",
				// UUID is missing
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), backMatter)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	// Test with invalid UUID format
	backMatter = oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				UUID:        "invalid-uuid",
				Title:       "Test Resource",
				Description: "Test resource description",
			},
		},
	}

	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), backMatter)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

// Test Update Back Matter endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateBackMatter() {
	arUUID := suite.createBasicAssessmentResults()

	// First create back matter
	backMatter := oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				UUID:        uuid.New().String(),
				Title:       "Test Resource",
				Description: "Test resource description",
			},
		},
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), backMatter)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	// Update back matter
	updatedBackMatter := oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				UUID:        uuid.New().String(),
				Title:       "Updated Resource",
				Description: "Updated resource description",
			},
			{
				UUID:        uuid.New().String(),
				Title:       "Second Resource",
				Description: "Second resource description",
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), updatedBackMatter)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.BackMatter]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.NotNil(response.Data.Resources)
	suite.Len(*response.Data.Resources, 2)
}

// Test Delete Back Matter endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestDeleteBackMatter() {
	arUUID := suite.createBasicAssessmentResults()

	// First create back matter
	backMatter := oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				UUID:        uuid.New().String(),
				Title:       "Test Resource",
				Description: "Test resource description",
			},
		},
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), backMatter)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	// Delete back matter
	rec, req := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code)

	// Verify deletion
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)
	var getResponse handler.GenericDataResponse[oscaltypes.BackMatter]
	err := json.Unmarshal(getRec.Body.Bytes(), &getResponse)
	suite.NoError(err)
	suite.NotNil(getResponse.Data.Resources)
	suite.Len(*getResponse.Data.Resources, 0) // Should be empty after deletion
}

// Test Get Back Matter Resources endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestGetBackMatterResources() {
	arUUID := suite.createBasicAssessmentResults()

	// First create back matter with resources
	backMatter := oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				UUID:        uuid.New().String(),
				Title:       "Resource 1",
				Description: "Resource 1 description",
			},
			{
				UUID:        uuid.New().String(),
				Title:       "Resource 2",
				Description: "Resource 2 description",
			},
		},
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), backMatter)
	suite.server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	// Verify the back matter was created with resources
	var createResponse handler.GenericDataResponse[oscaltypes.BackMatter]
	err := json.Unmarshal(createRec.Body.Bytes(), &createResponse)
	suite.NoError(err)
	if err != nil || createResponse.Data.Resources == nil {
		suite.T().Logf("Create back matter response body: %s", createRec.Body.String())
	}
	suite.NotNil(createResponse.Data.Resources)
	if createResponse.Data.Resources != nil {
		suite.T().Logf("Created back matter has %d resources", len(*createResponse.Data.Resources))
	}
	suite.Len(*createResponse.Data.Resources, 2)

	// Get resources
	rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		suite.T().Logf("Get resources response: %d, body: %s", rec.Code, rec.Body.String())
	}
	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataListResponse[oscaltypes.Resource]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.T().Logf("Get resources returned %d items", len(response.Data))
	suite.Len(response.Data, 2)
}

// Test Create Back Matter Resource endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateBackMatterResource() {
	arUUID := suite.createBasicAssessmentResults()

	resource := oscaltypes.Resource{
		UUID:        uuid.New().String(),
		Title:       "New Resource",
		Description: "New resource description",
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources", arUUID), resource)
	suite.server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusCreated, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.Resource]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal(resource.UUID, response.Data.UUID)
	suite.Equal(resource.Title, response.Data.Title)
}

// Test Update Back Matter Resource endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateBackMatterResource() {
	arUUID := suite.createBasicAssessmentResults()

	// First create a resource
	resource := oscaltypes.Resource{
		UUID:        uuid.New().String(),
		Title:       "Original Resource",
		Description: "Original description",
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources", arUUID), resource)
	suite.server.E().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		suite.T().Logf("Create resource response: %d, body: %s", createRec.Code, createRec.Body.String())
	}
	suite.Equal(http.StatusCreated, createRec.Code)

	// Parse the response to get the actual resource ID
	var createResponse handler.GenericDataResponse[oscaltypes.Resource]
	err := json.Unmarshal(createRec.Body.Bytes(), &createResponse)
	suite.NoError(err)
	resourceID := createResponse.Data.UUID

	// Update the resource
	resource.Title = "Updated Resource"
	resource.Description = "Updated description"
	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources/%s", arUUID, resourceID), resource)
	suite.server.E().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		suite.T().Logf("Update resource response: %d, body: %s", rec.Code, rec.Body.String())
	}
	suite.Equal(http.StatusOK, rec.Code)
	var response handler.GenericDataResponse[oscaltypes.Resource]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.NoError(err)
	suite.Equal("Updated Resource", response.Data.Title)
	suite.Equal("Updated description", response.Data.Description)
}

// Test Delete Back Matter Resource endpoint
func (suite *AssessmentResultsApiIntegrationSuite) TestDeleteBackMatterResource() {
	arUUID := suite.createBasicAssessmentResults()

	// First create a resource
	resource := oscaltypes.Resource{
		UUID:        uuid.New().String(),
		Title:       "Resource to Delete",
		Description: "This will be deleted",
	}
	createRec, createReq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources", arUUID), resource)
	suite.server.E().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		suite.T().Logf("Create resource response: %d, body: %s", createRec.Code, createRec.Body.String())
	}
	suite.Equal(http.StatusCreated, createRec.Code)

	// Parse the response to get the actual resource ID
	var createResponse handler.GenericDataResponse[oscaltypes.Resource]
	err := json.Unmarshal(createRec.Body.Bytes(), &createResponse)
	suite.NoError(err)
	resourceID := createResponse.Data.UUID

	// Delete the resource
	rec, req := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources/%s", arUUID, resourceID), nil)
	suite.server.E().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		suite.T().Logf("Delete resource response: %d, body: %s", rec.Code, rec.Body.String())
	}
	suite.Equal(http.StatusNoContent, rec.Code)

	// Verify deletion
	getRec, getReq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources", arUUID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)
	var getResponse handler.GenericDataListResponse[oscaltypes.Resource]
	err = json.Unmarshal(getRec.Body.Bytes(), &getResponse)
	suite.NoError(err)
	suite.Len(getResponse.Data, 0) // Should be empty after deletion
}

// Test Create Resource with invalid UUID
func (suite *AssessmentResultsApiIntegrationSuite) TestCreateResourceWithInvalidUUID() {
	arUUID := suite.createBasicAssessmentResults()

	resource := oscaltypes.Resource{
		UUID:        "invalid-uuid",
		Title:       "Test Resource",
		Description: "Test description",
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter/resources", arUUID), resource)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

// Test Update non-existent back matter
func (suite *AssessmentResultsApiIntegrationSuite) TestUpdateNonExistentBackMatter() {
	arUUID := suite.createBasicAssessmentResults()

	backMatter := oscaltypes.BackMatter{
		Resources: &[]oscaltypes.Resource{
			{
				UUID:        uuid.New().String(),
				Title:       "Test Resource",
				Description: "Test description",
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), backMatter)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)
}

// Test Delete non-existent back matter
func (suite *AssessmentResultsApiIntegrationSuite) TestDeleteNonExistentBackMatter() {
	arUUID := suite.createBasicAssessmentResults()

	rec, req := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/back-matter", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)
}

// Result sub-endpoints tests

// Helper function to create a result with sub-resources
func (suite *AssessmentResultsApiIntegrationSuite) createResultWithSubResources(arUUID string) string {
	// First create a result
	result := oscaltypes.Result{
		UUID:        uuid.New().String(),
		Title:       "Test Result",
		Description: "Test result description",
		Start:       time.Now(),
		ReviewedControls: oscaltypes.ReviewedControls{
			ControlSelections: []oscaltypes.AssessedControls{
				{
					IncludeControls: &[]oscaltypes.AssessedControlsSelectControlById{
						{ControlId: "ac-1"},
					},
				},
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results", arUUID), result)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	var resp handler.GenericDataResponse[oscaltypes.Result]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data.UUID
}

// Test Observations CRUD
func (suite *AssessmentResultsApiIntegrationSuite) TestResultObservationsCRUD() {
	arUUID := suite.createBasicAssessmentResults()
	resultUUID := suite.createResultWithSubResources(arUUID)

	// Create observation
	observation := oscaltypes.Observation{
		UUID:        uuid.New().String(),
		Description: "Test observation",
		Methods:     []string{"TEST", "INTERVIEW"},
		Types:       &[]string{"finding"},
		Subjects: &[]oscaltypes.SubjectReference{
			{
				SubjectUuid: uuid.New().String(),
				Type:        "component",
			},
		},
		Collected: time.Now(),
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/observations", arUUID, resultUUID), observation)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	var createResp handler.GenericDataResponse[oscaltypes.Observation]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &createResp))
	obsUUID := createResp.Data.UUID

	// Get observations
	rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/observations", arUUID, resultUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var listResp handler.GenericDataListResponse[oscaltypes.Observation]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &listResp))
	suite.Len(listResp.Data, 1)

	// Update observation
	observation.Description = "Updated observation"
	rec, req = suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/observations/%s", arUUID, resultUUID, obsUUID), observation)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	// Delete observation
	rec, req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/observations/%s", arUUID, resultUUID, obsUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code)
}

// Test Risks CRUD
func (suite *AssessmentResultsApiIntegrationSuite) TestResultRisksCRUD() {
	arUUID := suite.createBasicAssessmentResults()
	resultUUID := suite.createResultWithSubResources(arUUID)

	// Create risk
	risk := oscaltypes.Risk{
		UUID:        uuid.New().String(),
		Title:       "Test Risk",
		Description: "Test risk description",
		Statement:   "Risk statement",
		Status:      "open",
		RiskLog: &oscaltypes.RiskLog{
			Entries: []oscaltypes.RiskLogEntry{
				{
					UUID:        uuid.New().String(),
					Title:       "Initial Entry",
					Start:       time.Now(),
					Description: "Initial risk log entry",
				},
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/risks", arUUID, resultUUID), risk)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	var createResp handler.GenericDataResponse[oscaltypes.Risk]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &createResp))
	riskUUID := createResp.Data.UUID

	// Get risks
	rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/risks", arUUID, resultUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var listResp handler.GenericDataListResponse[oscaltypes.Risk]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &listResp))
	suite.Len(listResp.Data, 1)

	// Update risk
	risk.Title = "Updated Risk"
	rec, req = suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/risks/%s", arUUID, resultUUID, riskUUID), risk)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	// Delete risk
	rec, req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/risks/%s", arUUID, resultUUID, riskUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code)
}

// Test Findings CRUD
func (suite *AssessmentResultsApiIntegrationSuite) TestResultFindingsCRUD() {
	arUUID := suite.createBasicAssessmentResults()
	resultUUID := suite.createResultWithSubResources(arUUID)

	// Create finding
	finding := oscaltypes.Finding{
		UUID:        uuid.New().String(),
		Title:       "Test Finding",
		Description: "Test finding description",
		Target: oscaltypes.FindingTarget{
			Type:     "objective-id",
			TargetId: "ac-1_obj.1",
			Status: oscaltypes.ObjectiveStatus{
				State:  "not-satisfied",
				Reason: "Test reason",
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/findings", arUUID, resultUUID), finding)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	var createResp handler.GenericDataResponse[oscaltypes.Finding]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &createResp))
	findingUUID := createResp.Data.UUID

	// Get findings
	rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/findings", arUUID, resultUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var listResp handler.GenericDataListResponse[oscaltypes.Finding]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &listResp))
	suite.Len(listResp.Data, 1)

	// Update finding
	finding.Title = "Updated Finding"
	rec, req = suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/findings/%s", arUUID, resultUUID, findingUUID), finding)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	// Delete finding
	rec, req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/findings/%s", arUUID, resultUUID, findingUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code)
}

// Test Attestations CRUD
func (suite *AssessmentResultsApiIntegrationSuite) TestResultAttestationsCRUD() {
	arUUID := suite.createBasicAssessmentResults()
	resultUUID := suite.createResultWithSubResources(arUUID)

	// Create attestation
	attestation := oscaltypes.AttestationStatements{
		Parts: []oscaltypes.AssessmentPart{
			{
				UUID:  uuid.New().String(),
				Name:  "attestation",
				Ns:    "https://fedramp.gov/ns/oscal",
				Class: "fedramp",
				Title: "Attestation Statement",
				Prose: "I attest to the accuracy of this assessment.",
			},
		},
		ResponsibleParties: &[]oscaltypes.ResponsibleParty{
			{
				RoleId: "prepared-by",
				PartyUuids: []string{
					uuid.New().String(),
				},
			},
		},
	}

	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/attestations", arUUID, resultUUID), attestation)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Log the response
	if rec.Code != http.StatusCreated {
		suite.T().Logf("Create attestation response: %s", rec.Body.String())
	}

	// Get the created attestation ID from the database since AttestationStatements doesn't have a UUID field
	var createdAttestation relational.Attestation
	err := suite.DB.Where("result_id = ?", resultUUID).First(&createdAttestation).Error
	suite.NoError(err)
	suite.NotNil(createdAttestation.ID)
	suite.T().Logf("Created attestation ID: %v", createdAttestation.ID)

	var attestationUUID string
	if createdAttestation.ID != nil {
		attestationUUID = (*createdAttestation.ID).String()
	}
	suite.NotEmpty(attestationUUID, "Attestation UUID should not be empty")
	suite.T().Logf("Attestation UUID to use for update/delete: %s", attestationUUID)

	// Get attestations
	rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/attestations", arUUID, resultUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var listResp handler.GenericDataListResponse[oscaltypes.AttestationStatements]
	suite.NoError(json.Unmarshal(rec.Body.Bytes(), &listResp))
	suite.Len(listResp.Data, 1)

	// Update attestation
	attestation.Parts[0].Prose = "Updated attestation statement"
	rec, req = suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/attestations/%s", arUUID, resultUUID, attestationUUID), attestation)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	// Delete attestation
	rec, req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/attestations/%s", arUUID, resultUUID, attestationUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code)
}

// Test validation errors
func (suite *AssessmentResultsApiIntegrationSuite) TestResultSubResourcesValidation() {
	arUUID := suite.createBasicAssessmentResults()
	resultUUID := suite.createResultWithSubResources(arUUID)

	// Test invalid observation (missing required fields)
	invalidObs := oscaltypes.Observation{
		UUID: "invalid-uuid",
		// Missing required description and methods
	}
	rec, req := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/observations", arUUID, resultUUID), invalidObs)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	// Test invalid risk (missing required fields)
	invalidRisk := oscaltypes.Risk{
		UUID: uuid.New().String(),
		// Missing required title, description, statement, status
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/risks", arUUID, resultUUID), invalidRisk)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	// Test invalid finding (missing required fields)
	invalidFinding := oscaltypes.Finding{
		UUID:  uuid.New().String(),
		Title: "Test Finding",
		// Missing required description and target
		Target: oscaltypes.FindingTarget{},
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/findings", arUUID, resultUUID), invalidFinding)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	// Test invalid attestation (missing required parts)
	invalidAttestation := oscaltypes.AttestationStatements{
		// Missing required parts
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/attestations", arUUID, resultUUID), invalidAttestation)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

// TestResultAssociationEndpoints tests the association/dissociation endpoints for Result sub-resources
func (suite *AssessmentResultsApiIntegrationSuite) TestResultAssociationEndpoints() {
	// Create an assessment result with a result
	ar := oscaltypes.AssessmentResults{
		UUID: uuid.New().String(),
		Metadata: oscaltypes.Metadata{
			Title:        "Test AR for Association",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
		},
		ImportAp: oscaltypes.ImportAp{
			Href: fmt.Sprintf("assessment-plans/%s", uuid.New().String()),
		},
		Results: []oscaltypes.Result{
			{
				UUID:        uuid.New().String(),
				Title:       "Initial Result",
				Description: "Initial result for testing",
				Start:       time.Now().Add(-2 * time.Hour),
				ReviewedControls: oscaltypes.ReviewedControls{
					ControlSelections: []oscaltypes.AssessedControls{},
				},
			},
		},
	}
	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/assessment-results", ar)
	suite.server.E().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		suite.T().Logf("Failed to create assessment result: %s", rec.Body.String())
	}
	suite.Equal(http.StatusCreated, rec.Code)
	var arResp handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err := json.Unmarshal(rec.Body.Bytes(), &arResp)
	suite.NoError(err)
	arUUID := arResp.Data.UUID

	// Get the UUID of the result that was created with the assessment result
	// First, get the full assessment result to access the result UUID
	rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/full", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	var fullArResp handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err = json.Unmarshal(rec.Body.Bytes(), &fullArResp)
	suite.NoError(err)
	suite.NotEmpty(fullArResp.Data.Results)
	resultUUID := fullArResp.Data.Results[0].UUID

	// Create standalone observations, risks, and findings
	observation := suite.createStandaloneObservation()
	risk := suite.createStandaloneRisk()
	finding := suite.createStandaloneFinding()

	// Test observation association/dissociation
	suite.Run("ObservationAssociation", func() {
		// Get initial associated observations (should be empty)
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-observations", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var obsResp handler.GenericDataListResponse[*oscaltypes.Observation]
		err := json.Unmarshal(rec.Body.Bytes(), &obsResp)
		suite.NoError(err)
		suite.Empty(obsResp.Data)

		// Associate observation
		rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-observations/%s", arUUID, resultUUID, observation.UUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		// Get associated observations (should have one)
		rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-observations", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		err = json.Unmarshal(rec.Body.Bytes(), &obsResp)
		suite.NoError(err)
		suite.Len(obsResp.Data, 1)
		suite.Equal(observation.UUID, obsResp.Data[0].UUID)

		// Disassociate observation
		rec, req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-observations/%s", arUUID, resultUUID, observation.UUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusNoContent, rec.Code)

		// Get associated observations (should be empty again)
		rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-observations", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		err = json.Unmarshal(rec.Body.Bytes(), &obsResp)
		suite.NoError(err)
		suite.Empty(obsResp.Data)
	})

	// Test risk association/dissociation
	suite.Run("RiskAssociation", func() {
		// Get initial associated risks (should be empty)
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-risks", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var riskResp handler.GenericDataListResponse[*oscaltypes.Risk]
		err := json.Unmarshal(rec.Body.Bytes(), &riskResp)
		suite.NoError(err)
		suite.Empty(riskResp.Data)

		// Associate risk
		rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-risks/%s", arUUID, resultUUID, risk.UUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		// Get associated risks (should have one)
		rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-risks", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		err = json.Unmarshal(rec.Body.Bytes(), &riskResp)
		suite.NoError(err)
		suite.Len(riskResp.Data, 1)
		suite.Equal(risk.UUID, riskResp.Data[0].UUID)

		// Disassociate risk
		rec, req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-risks/%s", arUUID, resultUUID, risk.UUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusNoContent, rec.Code)

		// Get associated risks (should be empty again)
		rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-risks", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		err = json.Unmarshal(rec.Body.Bytes(), &riskResp)
		suite.NoError(err)
		suite.Empty(riskResp.Data)
	})

	// Test finding association/dissociation
	suite.Run("FindingAssociation", func() {
		// Get initial associated findings (should be empty)
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-findings", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var findingResp handler.GenericDataListResponse[*oscaltypes.Finding]
		err := json.Unmarshal(rec.Body.Bytes(), &findingResp)
		suite.NoError(err)
		suite.Empty(findingResp.Data)

		// Associate finding
		rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-findings/%s", arUUID, resultUUID, finding.UUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		// Get associated findings (should have one)
		rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-findings", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		err = json.Unmarshal(rec.Body.Bytes(), &findingResp)
		suite.NoError(err)
		suite.Len(findingResp.Data, 1)
		suite.Equal(finding.UUID, findingResp.Data[0].UUID)

		// Disassociate finding
		rec, req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-findings/%s", arUUID, resultUUID, finding.UUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusNoContent, rec.Code)

		// Get associated findings (should be empty again)
		rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/associated-findings", arUUID, resultUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		err = json.Unmarshal(rec.Body.Bytes(), &findingResp)
		suite.NoError(err)
		suite.Empty(findingResp.Data)
	})
}

// Helper functions for creating standalone resources
func (suite *AssessmentResultsApiIntegrationSuite) createStandaloneObservation() *oscaltypes.Observation {
	observation := &relational.Observation{}
	observation.UnmarshalOscal(oscaltypes.Observation{
		UUID:        uuid.New().String(),
		Description: "Standalone observation for testing",
		Methods:     []string{"TEST"},
		Collected:   time.Now(),
	})
	err := suite.DB.Create(observation).Error
	suite.NoError(err)

	return observation.MarshalOscal()
}

func (suite *AssessmentResultsApiIntegrationSuite) createStandaloneRisk() *oscaltypes.Risk {
	risk := &relational.Risk{}
	risk.UnmarshalOscal(oscaltypes.Risk{
		UUID:      uuid.New().String(),
		Title:     "Standalone risk for testing",
		Statement: "Risk statement",
		Status:    "open",
	})
	err := suite.DB.Create(risk).Error
	suite.NoError(err)

	return risk.MarshalOscal()
}

func (suite *AssessmentResultsApiIntegrationSuite) createStandaloneFinding() *oscaltypes.Finding {
	finding := &relational.Finding{}
	finding.UnmarshalOscal(oscaltypes.Finding{
		UUID:        uuid.New().String(),
		Title:       "Standalone finding for testing",
		Description: "Finding description",
	})
	err := suite.DB.Create(finding).Error
	suite.NoError(err)

	return finding.MarshalOscal()
}

// TestGetAllObservationsRisksFindings tests the endpoints that list all observations, risks, and findings
func (suite *AssessmentResultsApiIntegrationSuite) TestGetAllObservationsRisksFindings() {
	// First, create some standalone observations/risks/findings that aren't associated with any result
	standaloneObs := suite.createStandaloneObservation()
	standaloneRisk := suite.createStandaloneRisk()
	standaloneFinding := suite.createStandaloneFinding()

	// Create an assessment result with multiple results
	ar := oscaltypes.AssessmentResults{
		UUID: uuid.New().String(),
		Metadata: oscaltypes.Metadata{
			Title:        "Test AR for GetAll endpoints",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
		},
		ImportAp: oscaltypes.ImportAp{
			Href: fmt.Sprintf("assessment-plans/%s", uuid.New().String()),
		},
		Results: []oscaltypes.Result{
			{
				UUID:        uuid.New().String(),
				Title:       "First Result",
				Description: "First result with observations",
				Start:       time.Now().Add(-2 * time.Hour),
				ReviewedControls: oscaltypes.ReviewedControls{
					ControlSelections: []oscaltypes.AssessedControls{},
				},
			},
			{
				UUID:        uuid.New().String(),
				Title:       "Second Result",
				Description: "Second result with risks",
				Start:       time.Now().Add(-1 * time.Hour),
				ReviewedControls: oscaltypes.ReviewedControls{
					ControlSelections: []oscaltypes.AssessedControls{},
				},
			},
		},
	}
	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/assessment-results", ar)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)
	var arResp handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err := json.Unmarshal(rec.Body.Bytes(), &arResp)
	suite.NoError(err)
	arUUID := arResp.Data.UUID

	// Get the result UUIDs
	rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/full", arUUID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	var fullArResp handler.GenericDataResponse[oscaltypes.AssessmentResults]
	err = json.Unmarshal(rec.Body.Bytes(), &fullArResp)
	suite.NoError(err)
	result1UUID := fullArResp.Data.Results[0].UUID
	result2UUID := fullArResp.Data.Results[1].UUID

	// Create observations for first result
	obs1 := oscaltypes.Observation{
		UUID:        uuid.New().String(),
		Description: "Observation 1 for Result 1",
		Methods:     []string{"TEST"},
		Collected:   time.Now(),
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/observations", arUUID, result1UUID), obs1)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	obs2 := oscaltypes.Observation{
		UUID:        uuid.New().String(),
		Description: "Observation 2 for Result 1",
		Methods:     []string{"EXAMINE"},
		Collected:   time.Now(),
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/observations", arUUID, result1UUID), obs2)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Create risks for second result
	risk1 := oscaltypes.Risk{
		UUID:        uuid.New().String(),
		Title:       "Risk 1 for Result 2",
		Description: "Risk description 1",
		Statement:   "Risk statement 1",
		Status:      "open",
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/risks", arUUID, result2UUID), risk1)
	suite.server.E().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		suite.T().Logf("Failed to create risk: %s", rec.Body.String())
	}
	suite.Equal(http.StatusCreated, rec.Code)

	// Create findings for both results
	finding1 := oscaltypes.Finding{
		UUID:        uuid.New().String(),
		Title:       "Finding 1 for Result 1",
		Description: "Finding description 1",
		Target: oscaltypes.FindingTarget{
			Type:     "statement-id",
			TargetId: "ac-1_smt",
			Status: oscaltypes.ObjectiveStatus{
				State: "not-satisfied",
			},
			ImplementationStatus: &oscaltypes.ImplementationStatus{
				State: "not-applicable",
			},
		},
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/findings", arUUID, result1UUID), finding1)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	finding2 := oscaltypes.Finding{
		UUID:        uuid.New().String(),
		Title:       "Finding 2 for Result 2",
		Description: "Finding description 2",
		Target: oscaltypes.FindingTarget{
			Type:     "statement-id",
			TargetId: "ac-2_smt",
			Status: oscaltypes.ObjectiveStatus{
				State: "satisfied",
			},
			ImplementationStatus: &oscaltypes.ImplementationStatus{
				State: "implemented",
			},
		},
	}
	rec, req = suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/assessment-results/%s/results/%s/findings", arUUID, result2UUID), finding2)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code)

	// Test GetAllObservations
	suite.Run("GetAllObservations", func() {
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/observations", arUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var obsResp handler.GenericDataListResponse[*oscaltypes.Observation]
		err := json.Unmarshal(rec.Body.Bytes(), &obsResp)
		suite.NoError(err)
		// Should have 3 observations: 2 created for results + 1 standalone
		suite.Len(obsResp.Data, 3)

		// Verify we got all observations including the standalone one
		obsUUIDs := []string{}
		for _, obs := range obsResp.Data {
			obsUUIDs = append(obsUUIDs, obs.UUID)
		}
		suite.Contains(obsUUIDs, obs1.UUID)
		suite.Contains(obsUUIDs, obs2.UUID)
		suite.Contains(obsUUIDs, standaloneObs.UUID)
	})

	// Test GetAllRisks
	suite.Run("GetAllRisks", func() {
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/risks", arUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var riskResp handler.GenericDataListResponse[*oscaltypes.Risk]
		err := json.Unmarshal(rec.Body.Bytes(), &riskResp)
		suite.NoError(err)
		// Should have 2 risks: 1 created for results + 1 standalone
		suite.Len(riskResp.Data, 2)

		// Verify we got both risks including the standalone one
		riskUUIDs := []string{}
		for _, risk := range riskResp.Data {
			riskUUIDs = append(riskUUIDs, risk.UUID)
		}
		suite.Contains(riskUUIDs, risk1.UUID)
		suite.Contains(riskUUIDs, standaloneRisk.UUID)
	})

	// Test GetAllFindings
	suite.Run("GetAllFindings", func() {
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/findings", arUUID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var findingResp handler.GenericDataListResponse[*oscaltypes.Finding]
		err := json.Unmarshal(rec.Body.Bytes(), &findingResp)
		suite.NoError(err)
		// Should have 3 findings: 2 created for results + 1 standalone
		suite.Len(findingResp.Data, 3)

		// Verify we got all findings including the standalone one
		findingUUIDs := []string{}
		for _, finding := range findingResp.Data {
			findingUUIDs = append(findingUUIDs, finding.UUID)
		}
		suite.Contains(findingUUIDs, finding1.UUID)
		suite.Contains(findingUUIDs, finding2.UUID)
		suite.Contains(findingUUIDs, standaloneFinding.UUID)
	})
}

// Test control endpoints
func (suite *AssessmentResultsApiIntegrationSuite) TestControlEndpoints() {
	// Create a catalog with controls
	catalog := oscaltypes.Catalog{
		UUID: uuid.New().String(),
		Metadata: oscaltypes.Metadata{
			Title:        "Test Catalog",
			Version:      "1.0.0",
			LastModified: time.Now(),
		},
		Groups: &[]oscaltypes.Group{
			{
				ID:    "test-group",
				Title: "Test Group",
				Controls: &[]oscaltypes.Control{
					{
						ID:    "test-control-1",
						Title: "Test Control 1",
						Parts: &[]oscaltypes.Part{
							{
								ID:    "test-control-1_smt",
								Name:  "statement",
								Prose: "This is the control statement",
							},
							{
								ID:    "test-control-1_obj",
								Name:  "objective",
								Prose: "This is the control objective",
							},
						},
					},
					{
						ID:    "test-control-2",
						Title: "Test Control 2",
						Parts: &[]oscaltypes.Part{
							{
								ID:    "test-control-2_smt",
								Name:  "statement",
								Prose: "This is another control statement",
							},
						},
					},
				},
			},
		},
	}

	// Create the catalog in the database
	relationalCatalog := &relational.Catalog{}
	relationalCatalog.UnmarshalOscal(catalog)
	err := suite.DB.Create(relationalCatalog).Error
	suite.Require().NoError(err)

	// Create assessment results
	arID := suite.createBasicAssessmentResults()

	suite.Run("GetAvailableControls", func() {
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/available-controls", arID), nil)
		suite.server.E().ServeHTTP(rec, req)

		suite.Equal(http.StatusOK, rec.Code)

		var controlsResp handler.GenericDataListResponse[*oscaltypes.Control]
		err := json.Unmarshal(rec.Body.Bytes(), &controlsResp)
		suite.Require().NoError(err)

		// Should have 2 controls
		suite.Len(controlsResp.Data, 2)

		// Verify control IDs
		controlIDs := []string{}
		for _, control := range controlsResp.Data {
			controlIDs = append(controlIDs, control.ID)
			// Verify parts are included
			suite.NotNil(control.Parts)
		}
		suite.Contains(controlIDs, "test-control-1")
		suite.Contains(controlIDs, "test-control-2")
	})

	suite.Run("GetControlDetails", func() {
		// First get a control ID
		var control relational.Control
		err := suite.DB.Where("id = ?", "test-control-1").First(&control).Error
		suite.Require().NoError(err)

		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/control/%s", arID, control.ID), nil)
		suite.server.E().ServeHTTP(rec, req)

		suite.Equal(http.StatusOK, rec.Code)

		var controlResp handler.GenericDataResponse[*oscaltypes.Control]
		err = json.Unmarshal(rec.Body.Bytes(), &controlResp)
		suite.Require().NoError(err)

		// Verify control details
		suite.Equal("test-control-1", controlResp.Data.ID)
		suite.Equal("Test Control 1", controlResp.Data.Title)
		suite.NotNil(controlResp.Data.Parts)
		suite.Len(*controlResp.Data.Parts, 2)

		// Verify parts
		parts := *controlResp.Data.Parts
		partNames := []string{}
		for _, part := range parts {
			partNames = append(partNames, part.Name)
		}
		suite.Contains(partNames, "statement")
		suite.Contains(partNames, "objective")
	})

	suite.Run("GetControlDetailsNotFound", func() {
		nonExistentID := uuid.New().String()
		rec, req := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/assessment-results/%s/control/%s", arID, nonExistentID), nil)
		suite.server.E().ServeHTTP(rec, req)

		suite.Equal(http.StatusNotFound, rec.Code)
	})
}
