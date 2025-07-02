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

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

type SystemSecurityPlanApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *SystemSecurityPlanApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()
}

// Helper function to create authenticated requests
func (suite *SystemSecurityPlanApiIntegrationSuite) createRequest(method, path string, body interface{}) *http.Request {
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

// Factory function to create a basic test SSP
func (suite *SystemSecurityPlanApiIntegrationSuite) createBasicSSP() *oscalTypes_1_1_3.SystemSecurityPlan {
	sspUUID := uuid.New().String()
	now := time.Now()

	return &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspUUID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Test System Security Plan",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
			Parties: &[]oscalTypes_1_1_3.Party{
				{
					UUID: uuid.New().String(),
					Type: "organization",
					Name: "Test Organization",
				},
			},
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{
			Href: "https://example.com/profiles/nist-800-53-rev5-high",
		},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName:               "Test System",
			SystemNameShort:          "TESTSYS",
			Description:              "A test system for integration testing",
			SecuritySensitivityLevel: "high",
			SystemIds: []oscalTypes_1_1_3.SystemId{
				{
					IdentifierType: "https://ietf.org/rfc/rfc4122",
					ID:             uuid.New().String(),
				},
			},
			Status: oscalTypes_1_1_3.Status{
				State: "operational",
			},
			SystemInformation: oscalTypes_1_1_3.SystemInformation{
				InformationTypes: []oscalTypes_1_1_3.InformationType{
					{
						UUID:        uuid.New().String(),
						Title:       "Test Information Type",
						Description: "Test information type for testing",
					},
				},
			},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Users: []oscalTypes_1_1_3.SystemUser{
				{
					UUID:    uuid.New().String(),
					Title:   "System Administrator",
					RoleIds: &[]string{"system-admin", "security-admin"},
					AuthorizedPrivileges: &[]oscalTypes_1_1_3.AuthorizedPrivilege{
						{
							Title:              "Full Administrative Access",
							FunctionsPerformed: []string{"system-administration", "security-management"},
						},
					},
				},
			},
			Components: []oscalTypes_1_1_3.SystemComponent{
				{
					UUID:        uuid.New().String(),
					Type:        "software",
					Title:       "Test Application",
					Description: "Test application component",
					Status: oscalTypes_1_1_3.SystemComponentStatus{
						State: "operational",
					},
				},
			},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "Control implementation for test system",
			ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
				{
					UUID:      uuid.New().String(),
					ControlId: "ac-1",
					Statements: &[]oscalTypes_1_1_3.Statement{
						{
							StatementId: "ac-1_stmt.a",
							UUID:        uuid.New().String(),
							Remarks:     "Test statement implementation",
						},
					},
				},
			},
		},
	}
}

// Test creating a basic SSP
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateSSP() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

	ssp := suite.createBasicSSP()

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()

	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusCreated, resp.Code)

	var response handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
	err = json.Unmarshal(resp.Body.Bytes(), &response)
	suite.NoError(err)

	suite.Equal(ssp.UUID, response.Data.UUID)
	suite.Equal(ssp.Metadata.Title, response.Data.Metadata.Title)
	suite.Equal(ssp.SystemCharacteristics.SystemName, response.Data.SystemCharacteristics.SystemName)
}

// Test creating SSP with validation errors
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateSSPValidationErrors() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

	testCases := []struct {
		name        string
		modifySSP   func(*oscalTypes_1_1_3.SystemSecurityPlan)
		expectedMsg string
	}{
		{
			name: "missing UUID",
			modifySSP: func(ssp *oscalTypes_1_1_3.SystemSecurityPlan) {
				ssp.UUID = ""
			},
			expectedMsg: "UUID is required",
		},
		{
			name: "invalid UUID format",
			modifySSP: func(ssp *oscalTypes_1_1_3.SystemSecurityPlan) {
				ssp.UUID = "invalid-uuid"
			},
			expectedMsg: "invalid UUID format",
		},
		{
			name: "missing title",
			modifySSP: func(ssp *oscalTypes_1_1_3.SystemSecurityPlan) {
				ssp.Metadata.Title = ""
			},
			expectedMsg: "metadata.title is required",
		},
		{
			name: "missing version",
			modifySSP: func(ssp *oscalTypes_1_1_3.SystemSecurityPlan) {
				ssp.Metadata.Version = ""
			},
			expectedMsg: "metadata.version is required",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			ssp := suite.createBasicSSP()
			tc.modifySSP(ssp)

			req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
			resp := httptest.NewRecorder()

			server.E().ServeHTTP(resp, req)

			suite.Equal(http.StatusBadRequest, resp.Code)

			var errorResp api.Error
			err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
			suite.NoError(err)
			suite.Contains(errorResp.Errors["body"], tc.expectedMsg)
		})
	}
}

// Test retrieving SSP by ID
func (suite *SystemSecurityPlanApiIntegrationSuite) TestGetSSP() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Get SSP by ID
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s", ssp.UUID), nil)
	resp = httptest.NewRecorder()

	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusOK, resp.Code)

	var response handler.GenericDataResponse[*oscalTypes_1_1_3.SystemSecurityPlan]
	err = json.Unmarshal(resp.Body.Bytes(), &response)
	suite.NoError(err)

	suite.Equal(ssp.UUID, response.Data.UUID)
	suite.Equal(ssp.Metadata.Title, response.Data.Metadata.Title)
}

// Test retrieving non-existent SSP
func (suite *SystemSecurityPlanApiIntegrationSuite) TestGetSSPNotFound() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

	nonExistentUUID := uuid.New().String()
	req := suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s", nonExistentUUID), nil)
	resp := httptest.NewRecorder()

	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusNotFound, resp.Code)
}

// Test listing SSPs
func (suite *SystemSecurityPlanApiIntegrationSuite) TestListSSPs() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

	// Create multiple SSPs
	ssp1 := suite.createBasicSSP()
	ssp1.Metadata.Title = "First Test SSP"

	ssp2 := suite.createBasicSSP()
	ssp2.Metadata.Title = "Second Test SSP"

	// Create first SSP
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp1)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create second SSP
	req = suite.createRequest("POST", "/api/oscal/system-security-plans", ssp2)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// List SSPs
	req = suite.createRequest("GET", "/api/oscal/system-security-plans", nil)
	resp = httptest.NewRecorder()

	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusOK, resp.Code)

	var response handler.GenericDataListResponse[oscalTypes_1_1_3.SystemSecurityPlan]
	err = json.Unmarshal(resp.Body.Bytes(), &response)
	suite.NoError(err)

	suite.GreaterOrEqual(len(response.Data), 2)

	// Find our created SSPs
	foundSSP1, foundSSP2 := false, false
	for _, ssp := range response.Data {
		if ssp.UUID == ssp1.UUID {
			foundSSP1 = true
			suite.Equal("First Test SSP", ssp.Metadata.Title)
		}
		if ssp.UUID == ssp2.UUID {
			foundSSP2 = true
			suite.Equal("Second Test SSP", ssp.Metadata.Title)
		}
	}

	suite.True(foundSSP1, "First SSP not found in list")
	suite.True(foundSSP2, "Second SSP not found in list")
}

func TestSystemSecurityPlanApiIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SystemSecurityPlanApiIntegrationSuite))
}