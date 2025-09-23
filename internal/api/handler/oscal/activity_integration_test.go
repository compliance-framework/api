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

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/tests"
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
	metrics := api.NewMetricsHandler(context.Background(), suite.logger)
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config, metrics)
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

// Test that updating steps in an activity does not currently update the database (expected to fail)
func (suite *ActivityApiIntegrationSuite) TestUpdateActivitySteps() {
	// Create an activity with initial steps
	activityID := uuid.New()
	stepId := uuid.New()
	initialSteps := []oscalTypes_1_1_3.Step{
		{
			UUID:  stepId.String(),
			Title: "Initial Step 1",
		},
	}
	activity := &oscalTypes_1_1_3.Activity{
		UUID:        activityID.String(),
		Description: "Test Activity for Step Update",
		Steps:       &initialSteps,
	}

	rec, req := suite.createRequest(http.MethodPost, "/api/oscal/activities", activity)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, "Failed to create activity")

	// Update the activity: change steps (replace with new steps)
	updatedSteps := []oscalTypes_1_1_3.Step{
		{
			UUID:  stepId.String(),
			Title: "Updated Step 1",
		},
	}
	activity.Steps = &updatedSteps

	rec, req = suite.createRequest(http.MethodPut, fmt.Sprintf("/api/oscal/activities/%s", activityID.String()), activity)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, "Failed to update activity")

	// Fetch the activity from the API
	rec, req = suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/activities/%s", activityID.String()), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, "Failed to get activity after update")

	var resp struct {
		Data *oscalTypes_1_1_3.Activity `json:"data"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	suite.Require().NoError(err, "Failed to unmarshal get activity response")

	// The steps should match the updated steps, but currently they do not (expected to fail)
	suite.Require().NotNil(resp.Data, "No activity returned from get")
	fmt.Println((*resp.Data.Steps)[0])
	suite.Equal("Updated Step 1", (*resp.Data.Steps)[0].Title)
}
