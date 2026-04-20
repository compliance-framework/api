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
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

type SystemSecurityPlanApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *SystemSecurityPlanApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()
}

// Helper function to create authenticated requests
func (suite *SystemSecurityPlanApiIntegrationSuite) createRequest(method, path string, body any) *http.Request {
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

	componentUUID := uuid.New().String()

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
					UUID:        componentUUID,
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
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

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
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

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
				ssp.UUID = "invalid0-uuid-4mat-1234-567890123456"
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
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

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
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	nonExistentUUID := uuid.New().String()
	req := suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s", nonExistentUUID), nil)
	resp := httptest.NewRecorder()

	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusNotFound, resp.Code)
}

// Test listing SSPs
func (suite *SystemSecurityPlanApiIntegrationSuite) TestListSSPs() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

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

// Test creating a statement within an implemented requirement
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateImplementedRequirementStatement() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first (without statements)
	ssp := suite.createBasicSSP()
	// Remove statements from the SSP to create it cleanly
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = nil

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create an implemented requirement without statements
	implementedReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ac-1",
		Remarks:   "Test implemented requirement",
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", ssp.UUID), implementedReq)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	err = json.Unmarshal(resp.Body.Bytes(), &createResponse)
	suite.NoError(err)

	requirement := createResponse.Data

	// Create a new statement
	newStatement := oscalTypes_1_1_3.Statement{
		UUID:        uuid.New().String(),
		StatementId: "ac-1_stmt.a",
		Remarks:     "New statement implementation with detailed remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "implementation-status",
				Value: "implemented",
			},
			{
				Name:  "verification-method",
				Value: "test",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/documentation",
				MediaType: "application/pdf",
				Text:      "Implementation Documentation",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:  "system-administrator",
				Remarks: "Primary responsibility for implementation",
			},
			{
				RoleId:  "security-officer",
				Remarks: "Secondary responsibility for oversight",
			},
		},
	}

	// Create the statement
	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements",
		ssp.UUID, requirement.UUID), newStatement)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusCreated, resp.Code)

	var statementResponse handler.GenericDataResponse[oscalTypes_1_1_3.Statement]
	err = json.Unmarshal(resp.Body.Bytes(), &statementResponse)
	suite.NoError(err)

	// Verify the created statement
	createdStatement := statementResponse.Data
	suite.Equal(newStatement.UUID, createdStatement.UUID)
	suite.Equal(newStatement.StatementId, createdStatement.StatementId)
	suite.Equal("New statement implementation with detailed remarks", createdStatement.Remarks)

	// Verify properties
	suite.Require().NotNil(createdStatement.Props)
	suite.Len(*createdStatement.Props, 2)
	suite.Equal("implementation-status", (*createdStatement.Props)[0].Name)
	suite.Equal("implemented", (*createdStatement.Props)[0].Value)
	suite.Equal("verification-method", (*createdStatement.Props)[1].Name)
	suite.Equal("test", (*createdStatement.Props)[1].Value)

	// Verify links
	suite.Require().NotNil(createdStatement.Links)
	suite.Len(*createdStatement.Links, 1)
	suite.Equal("https://example.com/documentation", (*createdStatement.Links)[0].Href)
	suite.Equal("application/pdf", (*createdStatement.Links)[0].MediaType)
	suite.Equal("Implementation Documentation", (*createdStatement.Links)[0].Text)

	// Verify responsible roles
	suite.Require().NotNil(createdStatement.ResponsibleRoles)
	suite.Len(*createdStatement.ResponsibleRoles, 2)
	suite.Equal("system-administrator", (*createdStatement.ResponsibleRoles)[0].RoleId)
	suite.Equal("Primary responsibility for implementation", (*createdStatement.ResponsibleRoles)[0].Remarks)
	suite.Equal("security-officer", (*createdStatement.ResponsibleRoles)[1].RoleId)
	suite.Equal("Secondary responsibility for oversight", (*createdStatement.ResponsibleRoles)[1].Remarks)
}

// Test creating a statement with invalid IDs
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateImplementedRequirementStatementInvalidIDs() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Parse response to get the actual SSP UUID
	var createSSPResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
	err = json.Unmarshal(resp.Body.Bytes(), &createSSPResponse)
	suite.NoError(err)
	actualSSPUUID := createSSPResponse.Data.UUID

	testCases := []struct {
		name           string
		sspID          string
		reqID          string
		expectedStatus int
	}{
		{
			name:           "invalid SSP ID",
			sspID:          "invalid0-uuid-4mat-1234-567890123456",
			reqID:          uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid requirement ID",
			sspID:          actualSSPUUID,
			reqID:          "invalid0-uuid-4mat-1234-567890123456",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "non-existent SSP",
			sspID:          uuid.New().String(),
			reqID:          uuid.New().String(),
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "non-existent requirement",
			sspID:          actualSSPUUID,
			reqID:          uuid.New().String(),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			newStatement := oscalTypes_1_1_3.Statement{
				UUID:        uuid.New().String(),
				StatementId: "test-statement",
				Remarks:     "Test statement",
			}

			req := suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements",
				tc.sspID, tc.reqID), newStatement)
			resp := httptest.NewRecorder()
			server.E().ServeHTTP(resp, req)

			suite.Equal(tc.expectedStatus, resp.Code)
		})
	}
}

// Test updating a statement within an implemented requirement
func (suite *SystemSecurityPlanApiIntegrationSuite) TestUpdateImplementedRequirementStatement() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first (without statements)
	ssp := suite.createBasicSSP()
	// Remove statements from the SSP to create it cleanly
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = nil

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create an implemented requirement with statements
	implementedReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ac-1",
		Statements: &[]oscalTypes_1_1_3.Statement{
			{
				UUID:        uuid.New().String(),
				StatementId: "ac-1_stmt.a",
				Remarks:     "Initial statement implementation",
			},
		},
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", ssp.UUID), implementedReq)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	err = json.Unmarshal(resp.Body.Bytes(), &createResponse)
	suite.NoError(err)

	// Extract the requirement and statement IDs
	requirement := createResponse.Data
	suite.Require().NotNil(requirement.Statements)
	suite.Require().NotEmpty(*requirement.Statements)
	statement := (*requirement.Statements)[0]

	// Update the statement
	updatedStatement := oscalTypes_1_1_3.Statement{
		UUID:        statement.UUID,
		StatementId: statement.StatementId,
		Remarks:     "Updated statement implementation with new remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "updated-prop",
				Value: "updated-value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://updated-link.com",
				MediaType: "application/json",
				Text:      "Updated Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:  "updated-role",
				Remarks: "Updated role remarks",
			},
		},
	}

	// Update the statement
	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s",
		ssp.UUID, requirement.UUID, statement.UUID), updatedStatement)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusOK, resp.Code)

	var updateResponse handler.GenericDataResponse[oscalTypes_1_1_3.Statement]
	err = json.Unmarshal(resp.Body.Bytes(), &updateResponse)
	suite.NoError(err)

	// Verify the updated statement
	suite.Equal(statement.UUID, updateResponse.Data.UUID)
	suite.Equal(statement.StatementId, updateResponse.Data.StatementId)
	suite.Equal("Updated statement implementation with new remarks", updateResponse.Data.Remarks)
	suite.Require().NotNil(updateResponse.Data.Props)
	suite.Len(*updateResponse.Data.Props, 1)
	suite.Equal("updated-prop", (*updateResponse.Data.Props)[0].Name)
	suite.Equal("updated-value", (*updateResponse.Data.Props)[0].Value)
	suite.Require().NotNil(updateResponse.Data.Links)
	suite.Len(*updateResponse.Data.Links, 1)
	suite.Equal("https://updated-link.com", (*updateResponse.Data.Links)[0].Href)
	suite.Require().NotNil(updateResponse.Data.ResponsibleRoles)
	suite.Len(*updateResponse.Data.ResponsibleRoles, 1)
	suite.Equal("updated-role", (*updateResponse.Data.ResponsibleRoles)[0].RoleId)
}

// Test updating a by-component within an implemented requirement (requirement-level)
func (suite *SystemSecurityPlanApiIntegrationSuite) TestUpdateImplementedRequirementByComponent() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	ssp := suite.createBasicSSP()
	componentUuid := ssp.SystemImplementation.Components[0].UUID

	// Remove statements to keep setup minimal for requirement-level by-components
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = nil

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	implementedReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ac-1",
		ByComponents: &[]oscalTypes_1_1_3.ByComponent{
			{
				UUID:          uuid.New().String(),
				ComponentUuid: componentUuid,
				Description:   "Test requirement-level by component",
			},
		},
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", ssp.UUID), implementedReq)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	err = json.Unmarshal(resp.Body.Bytes(), &createResponse)
	suite.NoError(err)

	requirement := createResponse.Data
	suite.Require().NotNil(requirement.ByComponents)
	suite.Require().NotEmpty(*requirement.ByComponents)
	firstByComponent := (*requirement.ByComponents)[0]

	updatedByComponent := oscalTypes_1_1_3.ByComponent{
		UUID:          firstByComponent.UUID,
		ComponentUuid: firstByComponent.ComponentUuid,
		Description:   "Updated requirement-level by component",
		Remarks:       "Updated requirement-level remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "updated-prop",
				Value: "updated-value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://updated-link.com",
				MediaType: "application/json",
				Text:      "Updated Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:  "updated-role",
				Remarks: "Updated role remarks",
			},
		},
	}

	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/by-components/%s",
		ssp.UUID, requirement.UUID, updatedByComponent.UUID), updatedByComponent)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusOK, resp.Code)

	var updateResponse handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
	err = json.Unmarshal(resp.Body.Bytes(), &updateResponse)
	suite.NoError(err)

	suite.Equal(updatedByComponent.UUID, updateResponse.Data.UUID)
	suite.Equal(updatedByComponent.ComponentUuid, updateResponse.Data.ComponentUuid)
	suite.Equal("Updated requirement-level by component", updateResponse.Data.Description)
	suite.Equal("Updated requirement-level remarks", updateResponse.Data.Remarks)
	suite.Require().NotNil(updateResponse.Data.Props)
	suite.Len(*updateResponse.Data.Props, 1)
	suite.Equal("updated-prop", (*updateResponse.Data.Props)[0].Name)
	suite.Equal("updated-value", (*updateResponse.Data.Props)[0].Value)
	suite.Require().NotNil(updateResponse.Data.Links)
	suite.Len(*updateResponse.Data.Links, 1)
	suite.Equal("https://updated-link.com", (*updateResponse.Data.Links)[0].Href)
	suite.Require().NotNil(updateResponse.Data.ResponsibleRoles)
	suite.Len(*updateResponse.Data.ResponsibleRoles, 1)
	suite.Equal("updated-role", (*updateResponse.Data.ResponsibleRoles)[0].RoleId)
}

// Test updating a by-component within a statement within an implemented requirement
func (suite *SystemSecurityPlanApiIntegrationSuite) TestUpdateImplementedRequirementStatementByComponent() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first (without statements)
	ssp := suite.createBasicSSP()

	componentUuid := ssp.SystemImplementation.Components[0].UUID

	// Remove statements from the SSP to create it cleanly
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = nil

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create an implemented requirement with statements
	implementedReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ac-1",
		Statements: &[]oscalTypes_1_1_3.Statement{
			{
				UUID:        uuid.New().String(),
				StatementId: "ac-1_stmt.a",
				Remarks:     "Initial statement implementation",
				ByComponents: &[]oscalTypes_1_1_3.ByComponent{
					{
						UUID:          uuid.New().String(),
						Description:   "Test By Component",
						ComponentUuid: componentUuid,
					},
				},
			},
		},
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", ssp.UUID), implementedReq)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	err = json.Unmarshal(resp.Body.Bytes(), &createResponse)
	suite.NoError(err)

	// Extract the requirement and statement IDs
	requirement := createResponse.Data
	suite.Require().NotNil(requirement.Statements)
	suite.Require().NotEmpty(*requirement.Statements)

	statement := (*requirement.Statements)[0]

	firstByComponent := (*statement.ByComponents)[0]

	// // Update the statement's by component

	updatedByComponent := oscalTypes_1_1_3.ByComponent{
		ComponentUuid: firstByComponent.ComponentUuid,
		UUID:          firstByComponent.UUID,
		Description:   firstByComponent.Description,
		Remarks:       "Updated by-component with new remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "updated-prop",
				Value: "updated-value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://updated-link.com",
				MediaType: "application/json",
				Text:      "Updated Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:  "updated-role",
				Remarks: "Updated role remarks",
			},
		},
	}

	// // Update the statement
	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/by-components/%s",
		ssp.UUID, requirement.UUID, statement.UUID, updatedByComponent.UUID), updatedByComponent)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusOK, resp.Code)

	var updateResponse handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
	err = json.Unmarshal(resp.Body.Bytes(), &updateResponse)
	suite.NoError(err)

	// Verify the updated statement
	suite.Equal(updatedByComponent.UUID, updateResponse.Data.UUID)
	suite.Equal(updatedByComponent.ComponentUuid, updateResponse.Data.ComponentUuid)
	suite.Equal("Updated by-component with new remarks", updateResponse.Data.Remarks)
	suite.Require().NotNil(updateResponse.Data.Props)
	suite.Len(*updateResponse.Data.Props, 1)
	suite.Equal("updated-prop", (*updateResponse.Data.Props)[0].Name)
	suite.Equal("updated-value", (*updateResponse.Data.Props)[0].Value)
	suite.Require().NotNil(updateResponse.Data.Links)
	suite.Len(*updateResponse.Data.Links, 1)
	suite.Equal("https://updated-link.com", (*updateResponse.Data.Links)[0].Href)
	suite.Require().NotNil(updateResponse.Data.ResponsibleRoles)
	suite.Len(*updateResponse.Data.ResponsibleRoles, 1)
	suite.Equal("updated-role", (*updateResponse.Data.ResponsibleRoles)[0].RoleId)
}

// Test deleting a by-component within a statement within an implemented requirement
func (suite *SystemSecurityPlanApiIntegrationSuite) TestDeleteImplementedRequirementStatementByComponent() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first (without statements)
	ssp := suite.createBasicSSP()

	componentUuid := ssp.SystemImplementation.Components[0].UUID

	// Remove statements from the SSP to create it cleanly
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = nil

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	byComponentUuid := uuid.New().String()

	// Create an implemented requirement with statements
	implementedReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ac-1",
		Statements: &[]oscalTypes_1_1_3.Statement{
			{
				UUID:        uuid.New().String(),
				StatementId: "ac-1_stmt.a",
				Remarks:     "Initial statement implementation",
				ByComponents: &[]oscalTypes_1_1_3.ByComponent{
					{
						UUID:          byComponentUuid,
						Description:   "Test By Component",
						ComponentUuid: componentUuid,
					},
				},
			},
		},
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", ssp.UUID), implementedReq)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	err = json.Unmarshal(resp.Body.Bytes(), &createResponse)
	suite.NoError(err)

	// Extract the requirement and statement IDs
	requirement := createResponse.Data
	suite.Require().NotNil(requirement.Statements)
	suite.Require().NotEmpty(*requirement.Statements)

	statement := (*requirement.Statements)[0]

	// Delete the by-component
	req = suite.createRequest("DELETE", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/by-components/%s",
		ssp.UUID, requirement.UUID, statement.UUID, byComponentUuid), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusNoContent, resp.Code)

	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/by-components/%s",
		ssp.UUID, requirement.UUID, statement.UUID, byComponentUuid), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusNotFound, resp.Code)
}

// Test creating a by-component within a statement within an implemented requirement
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateImplementedRequirementStatementByComponent() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first (without statements)
	ssp := suite.createBasicSSP()

	componentUuid := ssp.SystemImplementation.Components[0].UUID

	// Remove statements from the SSP to create it cleanly
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = nil

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create an implemented requirement with statements
	implementedReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ac-1",
		Statements: &[]oscalTypes_1_1_3.Statement{
			{
				UUID:        uuid.New().String(),
				StatementId: "ac-1_stmt.a",
				Remarks:     "Initial statement implementation",
				ByComponents: &[]oscalTypes_1_1_3.ByComponent{
					{
						UUID:          uuid.New().String(),
						Description:   "Test By Component",
						ComponentUuid: componentUuid,
					},
				},
			},
		},
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", ssp.UUID), implementedReq)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createIRResponse handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	err = json.Unmarshal(resp.Body.Bytes(), &createIRResponse)
	suite.NoError(err)

	// Extract the requirement and statement IDs
	requirement := createIRResponse.Data
	suite.Require().NotNil(requirement.Statements)
	suite.Require().NotEmpty(*requirement.Statements)

	statement := (*requirement.Statements)[0]

	firstByComponent := (*statement.ByComponents)[0]

	// Create the statement's by component

	newByComponent := oscalTypes_1_1_3.ByComponent{
		ComponentUuid: firstByComponent.ComponentUuid,
		UUID:          uuid.New().String(),
		Description:   "New ByComponent",
		Remarks:       "New by-component with new remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "new-prop",
				Value: "new-value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://new-link.com",
				MediaType: "application/json",
				Text:      "New Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:  "new-role",
				Remarks: "New role remarks",
			},
		},
		ImplementationStatus: &oscalTypes_1_1_3.ImplementationStatus{
			State:   "implemented",
			Remarks: "Test Remarks",
		},
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/by-components",
		ssp.UUID, requirement.UUID, statement.UUID), newByComponent)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusCreated, resp.Code)

	var createBCResponse handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
	err = json.Unmarshal(resp.Body.Bytes(), &createBCResponse)
	suite.NoError(err)
}

// Test that creating a by-component with an invalid implementation status state returns 400
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateByComponentInvalidImplementationStatus() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)

	ssp := suite.loadTestSSP()
	componentUuid := ssp.SystemImplementation.Components[0].UUID
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = nil

	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	implementedReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ac-1",
		Statements: &[]oscalTypes_1_1_3.Statement{
			{
				UUID:        uuid.New().String(),
				StatementId: "ac-1_stmt.a",
				ByComponents: &[]oscalTypes_1_1_3.ByComponent{
					{
						UUID:          uuid.New().String(),
						Description:   "Test By Component",
						ComponentUuid: componentUuid,
					},
				},
			},
		},
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", ssp.UUID), implementedReq)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createIRResponse handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	err = json.Unmarshal(resp.Body.Bytes(), &createIRResponse)
	suite.NoError(err)

	requirement := createIRResponse.Data
	suite.Require().NotNil(requirement.Statements)
	suite.Require().NotEmpty(*requirement.Statements)
	statement := (*requirement.Statements)[0]

	// Invalid state should be rejected
	invalidBC := oscalTypes_1_1_3.ByComponent{
		ComponentUuid: componentUuid,
		UUID:          uuid.New().String(),
		Description:   "Invalid status BC",
		ImplementationStatus: &oscalTypes_1_1_3.ImplementationStatus{
			State: "Implemented",
		},
	}
	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/by-components",
		ssp.UUID, requirement.UUID, statement.UUID), invalidBC)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// Empty state with present implementation-status object should be rejected
	emptyStateBC := oscalTypes_1_1_3.ByComponent{
		ComponentUuid: componentUuid,
		UUID:          uuid.New().String(),
		Description:   "Empty status state BC",
		ImplementationStatus: &oscalTypes_1_1_3.ImplementationStatus{
			State:   "",
			Remarks: "Has remarks but no state",
		},
	}
	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/by-components",
		ssp.UUID, requirement.UUID, statement.UUID), emptyStateBC)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// Omitted implementation-status should be accepted
	noStatusBC := oscalTypes_1_1_3.ByComponent{
		ComponentUuid: componentUuid,
		UUID:          uuid.New().String(),
		Description:   "No status BC",
	}
	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/by-components",
		ssp.UUID, requirement.UUID, statement.UUID), noStatusBC)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)
}

// Test updating a statement with invalid IDs
func (suite *SystemSecurityPlanApiIntegrationSuite) TestUpdateImplementedRequirementStatementInvalidIDs() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Parse response to get the actual SSP UUID
	var createSSPResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
	err = json.Unmarshal(resp.Body.Bytes(), &createSSPResponse)
	suite.NoError(err)
	actualSSPUUID := createSSPResponse.Data.UUID

	testCases := []struct {
		name           string
		sspID          string
		reqID          string
		stmtID         string
		expectedStatus int
	}{
		{
			name:           "invalid SSP ID",
			sspID:          "invalid0-uuid-4mat-1234-567890123456",
			reqID:          uuid.New().String(),
			stmtID:         uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid requirement ID",
			sspID:          actualSSPUUID,
			reqID:          "invalid0-uuid-4mat-1234-567890123456",
			stmtID:         uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid statement ID",
			sspID:          actualSSPUUID,
			reqID:          uuid.New().String(),
			stmtID:         "invalid0-uuid-4mat-1234-567890123456",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "non-existent SSP",
			sspID:          uuid.New().String(),
			reqID:          uuid.New().String(),
			stmtID:         uuid.New().String(),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			updatedStatement := oscalTypes_1_1_3.Statement{
				UUID:        uuid.New().String(),
				StatementId: "test-statement",
				Remarks:     "Test statement",
			}

			req := suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s",
				tc.sspID, tc.reqID, tc.stmtID), updatedStatement)
			resp := httptest.NewRecorder()
			server.E().ServeHTTP(resp, req)

			suite.Equal(tc.expectedStatus, resp.Code)
		})
	}
}

// Test system implementation CRUD operations
func (suite *SystemSecurityPlanApiIntegrationSuite) TestSystemImplementationCRUD() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Test GET system implementation
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var getResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]
	err = json.Unmarshal(resp.Body.Bytes(), &getResponse)
	suite.NoError(err)
	suite.NotNil(getResponse.Data.Users)
	suite.NotNil(getResponse.Data.Components)

	// Test UPDATE system implementation
	updatedSystemImpl := oscalTypes_1_1_3.SystemImplementation{
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "environment",
				Value: "production",
			},
			{
				Name:  "security-level",
				Value: "high",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/system-architecture",
				MediaType: "application/pdf",
				Text:      "System Architecture Document",
			},
		},
		Users: []oscalTypes_1_1_3.SystemUser{
			{
				UUID:    uuid.New().String(),
				Title:   "Updated System Administrator",
				RoleIds: &[]string{"admin", "security-admin"},
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
				Title:       "Updated Test Application",
				Description: "Updated test application component",
				Props: &[]oscalTypes_1_1_3.Property{
					{
						Name:  "version",
						Value: "2.0.0",
					},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{
						Href: "https://example.com/app-docs",
						Text: "Application Documentation",
					},
				},
				Status: oscalTypes_1_1_3.SystemComponentStatus{
					State: "operational",
				},
			},
		},
		InventoryItems: &[]oscalTypes_1_1_3.InventoryItem{
			{
				UUID:        uuid.New().String(),
				Description: "Test Inventory Item",
				Props: &[]oscalTypes_1_1_3.Property{
					{
						Name:  "asset-type",
						Value: "hardware",
					},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{
						Href: "https://example.com/inventory",
						Text: "Inventory Management System",
					},
				},
				ResponsibleParties: &[]oscalTypes_1_1_3.ResponsibleParty{
					{
						RoleId:     "asset-manager",
						PartyUuids: []string{"org-1"},
					},
				},
			},
		},
		LeveragedAuthorizations: &[]oscalTypes_1_1_3.LeveragedAuthorization{
			{
				UUID:  uuid.New().String(),
				Title: "Cloud Platform Authorization",
				Links: &[]oscalTypes_1_1_3.Link{
					{
						Href: "https://example.com/cloud-auth",
						Text: "Cloud Authorization Documentation",
					},
				},
				PartyUuid:      uuid.New().String(),
				DateAuthorized: time.Now().Format("2006-01-02"),
			},
		},
		Remarks: "Updated system implementation with comprehensive configuration",
	}

	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation", ssp.UUID), updatedSystemImpl)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var updateResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]
	err = json.Unmarshal(resp.Body.Bytes(), &updateResponse)
	suite.NoError(err)

	// Verify updated fields
	suite.Equal("Updated system implementation with comprehensive configuration", updateResponse.Data.Remarks)
	suite.Require().NotNil(updateResponse.Data.Props)
	suite.Len(*updateResponse.Data.Props, 2)
	suite.Equal("environment", (*updateResponse.Data.Props)[0].Name)
	suite.Equal("production", (*updateResponse.Data.Props)[0].Value)

	suite.Require().NotNil(updateResponse.Data.Links)
	suite.Len(*updateResponse.Data.Links, 1)
	suite.Equal("https://example.com/system-architecture", (*updateResponse.Data.Links)[0].Href)

	suite.Require().NotNil(updateResponse.Data.InventoryItems)
	suite.Len(*updateResponse.Data.InventoryItems, 1)
	suite.Equal("Test Inventory Item", (*updateResponse.Data.InventoryItems)[0].Description)

	suite.Require().NotNil(updateResponse.Data.LeveragedAuthorizations)
	suite.Len(*updateResponse.Data.LeveragedAuthorizations, 1)
	suite.Equal("Cloud Platform Authorization", (*updateResponse.Data.LeveragedAuthorizations)[0].Title)
}

// Test system implementation users CRUD operations
func (suite *SystemSecurityPlanApiIntegrationSuite) TestSystemImplementationUsersCRUD() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Test GET users
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/users", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var getUsersResponse handler.GenericDataListResponse[oscalTypes_1_1_3.SystemUser]
	err = json.Unmarshal(resp.Body.Bytes(), &getUsersResponse)
	suite.NoError(err)
	suite.NotEmpty(getUsersResponse.Data) // Should have the initial user

	// Test CREATE user
	newUser := oscalTypes_1_1_3.SystemUser{
		UUID:    uuid.New().String(),
		Title:   "Security Officer",
		RoleIds: &[]string{"security-officer", "auditor"},
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "clearance-level",
				Value: "secret",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href: "https://example.com/user-profile",
				Text: "User Profile",
			},
		},
		AuthorizedPrivileges: &[]oscalTypes_1_1_3.AuthorizedPrivilege{
			{
				Title:              "Security Management",
				FunctionsPerformed: []string{"security-monitoring", "compliance-auditing"},
			},
		},
		Remarks: "Responsible for security oversight and compliance monitoring",
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/users", ssp.UUID), newUser)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createUserResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]
	err = json.Unmarshal(resp.Body.Bytes(), &createUserResponse)
	suite.NoError(err)
	suite.Equal("Security Officer", createUserResponse.Data.Title)
	suite.Equal("Responsible for security oversight and compliance monitoring", createUserResponse.Data.Remarks)

	userID := createUserResponse.Data.UUID

	// Test UPDATE user
	updatedUser := oscalTypes_1_1_3.SystemUser{
		UUID:    userID,
		Title:   "Senior Security Officer",
		RoleIds: &[]string{"senior-security-officer", "compliance-manager"},
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "clearance-level",
				Value: "top-secret",
			},
			{
				Name:  "experience-years",
				Value: "10",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href: "https://example.com/senior-user-profile",
				Text: "Senior User Profile",
			},
		},
		AuthorizedPrivileges: &[]oscalTypes_1_1_3.AuthorizedPrivilege{
			{
				Title:              "Advanced Security Management",
				FunctionsPerformed: []string{"security-architecture", "risk-management", "compliance-oversight"},
			},
		},
		Remarks: "Senior security officer with advanced privileges and oversight responsibilities",
	}

	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/users/%s", ssp.UUID, userID), updatedUser)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var updateUserResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]
	err = json.Unmarshal(resp.Body.Bytes(), &updateUserResponse)
	suite.NoError(err)
	suite.Equal("Senior Security Officer", updateUserResponse.Data.Title)
	suite.Equal("Senior security officer with advanced privileges and oversight responsibilities", updateUserResponse.Data.Remarks)

	// Verify props
	suite.Require().NotNil(updateUserResponse.Data.Props)
	suite.Len(*updateUserResponse.Data.Props, 2)
	suite.Equal("clearance-level", (*updateUserResponse.Data.Props)[0].Name)
	suite.Equal("top-secret", (*updateUserResponse.Data.Props)[0].Value)

	// Test DELETE user
	req = suite.createRequest("DELETE", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/users/%s", ssp.UUID, userID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify user is deleted
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/users", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var finalUsersResponse handler.GenericDataListResponse[oscalTypes_1_1_3.SystemUser]
	err = json.Unmarshal(resp.Body.Bytes(), &finalUsersResponse)
	suite.NoError(err)

	// Should not contain the deleted user
	for _, user := range finalUsersResponse.Data {
		suite.NotEqual(userID, user.UUID)
	}
}

// Test system implementation components CRUD operations
func (suite *SystemSecurityPlanApiIntegrationSuite) TestSystemImplementationComponentsCRUD() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Test GET components
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var getComponentsResponse handler.GenericDataListResponse[oscalTypes_1_1_3.SystemComponent]
	err = json.Unmarshal(resp.Body.Bytes(), &getComponentsResponse)
	suite.NoError(err)
	suite.NotEmpty(getComponentsResponse.Data) // Should have the initial component

	// Test CREATE component
	newComponent := oscalTypes_1_1_3.SystemComponent{
		UUID:        uuid.New().String(),
		Type:        "service",
		Title:       "Authentication Service",
		Description: "Centralized authentication and authorization service",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "version",
				Value: "3.2.1",
			},
			{
				Name:  "vendor",
				Value: "ACME Corp",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/auth-service-docs",
				MediaType: "text/html",
				Text:      "Authentication Service Documentation",
			},
		},
		Status: oscalTypes_1_1_3.SystemComponentStatus{
			State: "operational",
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:  "system-administrator",
				Remarks: "Primary administrator for authentication service",
			},
		},
		Remarks: "Critical authentication service providing SSO capabilities",
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components", ssp.UUID), newComponent)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createComponentResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
	err = json.Unmarshal(resp.Body.Bytes(), &createComponentResponse)
	suite.NoError(err)
	suite.Equal("Authentication Service", createComponentResponse.Data.Title)
	suite.Equal("service", createComponentResponse.Data.Type)
	suite.Equal("Critical authentication service providing SSO capabilities", createComponentResponse.Data.Remarks)

	componentID := createComponentResponse.Data.UUID

	// Test UPDATE component
	updatedComponent := oscalTypes_1_1_3.SystemComponent{
		UUID:        componentID,
		Type:        "service",
		Title:       "Enhanced Authentication Service",
		Description: "Enhanced centralized authentication and authorization service with MFA support",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "version",
				Value: "4.0.0",
			},
			{
				Name:  "vendor",
				Value: "ACME Corp",
			},
			{
				Name:  "mfa-enabled",
				Value: "true",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/enhanced-auth-service-docs",
				MediaType: "text/html",
				Text:      "Enhanced Authentication Service Documentation",
			},
		},
		Status: oscalTypes_1_1_3.SystemComponentStatus{
			State: "operational",
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:  "system-administrator",
				Remarks: "Primary administrator for enhanced authentication service",
			},
			{
				RoleId:  "security-officer",
				Remarks: "Security oversight for MFA implementation",
			},
		},
		Remarks: "Enhanced authentication service with multi-factor authentication capabilities",
	}

	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components/%s", ssp.UUID, componentID), updatedComponent)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var updateComponentResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
	err = json.Unmarshal(resp.Body.Bytes(), &updateComponentResponse)
	suite.NoError(err)
	suite.Equal("Enhanced Authentication Service", updateComponentResponse.Data.Title)
	suite.Equal("Enhanced authentication service with multi-factor authentication capabilities", updateComponentResponse.Data.Remarks)

	// Verify props
	suite.Require().NotNil(updateComponentResponse.Data.Props)
	suite.Len(*updateComponentResponse.Data.Props, 3)
	suite.Equal("version", (*updateComponentResponse.Data.Props)[0].Name)
	suite.Equal("4.0.0", (*updateComponentResponse.Data.Props)[0].Value)
	suite.Equal("mfa-enabled", (*updateComponentResponse.Data.Props)[2].Name)
	suite.Equal("true", (*updateComponentResponse.Data.Props)[2].Value)

	risk := riskrel.Risk{
		Title:       "Test risk for component cleanup",
		Description: "Risk used to verify component link cleanup",
		Status:      string(riskrel.RiskStatusOpen),
		SSPID:       uuid.MustParse(ssp.UUID),
		SourceType:  string(riskrel.RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}
	suite.Require().NoError(suite.DB.Create(&risk).Error)
	suite.Require().NotNil(risk.ID)

	suite.Require().NoError(suite.DB.Create(&riskrel.RiskComponentLink{
		RiskID:      *risk.ID,
		ComponentID: uuid.MustParse(componentID),
	}).Error)

	componentUUID := uuid.MustParse(componentID)
	byComponentID := uuid.New()
	parentType := "statements"
	statementUUID := uuid.MustParse((*ssp.ControlImplementation.ImplementedRequirements[0].Statements)[0].UUID)
	suite.Require().NoError(suite.DB.Create(&relational.ByComponent{
		UUIDModel:     relational.UUIDModel{ID: &byComponentID},
		ParentID:      &statementUUID,
		ParentType:    &parentType,
		ComponentUUID: componentUUID,
		Description:   "Test by-component bound to deleted component",
	}).Error)

	// Test DELETE component
	req = suite.createRequest("DELETE", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components/%s", ssp.UUID, componentID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNoContent, resp.Code)

	var riskComponentLinkCount int64
	suite.Require().NoError(suite.DB.Model(&riskrel.RiskComponentLink{}).
		Where("component_id = ?", componentUUID).
		Count(&riskComponentLinkCount).Error)
	suite.Equal(int64(0), riskComponentLinkCount)

	var byComponentCount int64
	suite.Require().NoError(suite.DB.Model(&relational.ByComponent{}).
		Where("component_uuid = ?", componentUUID).
		Count(&byComponentCount).Error)
	suite.Equal(int64(0), byComponentCount)

	// Verify component is deleted
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var finalComponentsResponse handler.GenericDataListResponse[oscalTypes_1_1_3.SystemComponent]
	err = json.Unmarshal(resp.Body.Bytes(), &finalComponentsResponse)
	suite.NoError(err)

	// Should not contain the deleted component
	for _, component := range finalComponentsResponse.Data {
		suite.NotEqual(componentID, component.UUID)
	}
}

// Test system implementation inventory items CRUD operations
func (suite *SystemSecurityPlanApiIntegrationSuite) TestSystemImplementationInventoryItemsCRUD() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Test GET inventory items
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/inventory-items", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var getInventoryResponse handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]
	err = json.Unmarshal(resp.Body.Bytes(), &getInventoryResponse)
	suite.NoError(err)

	// Test CREATE inventory item
	newInventoryItem := oscalTypes_1_1_3.InventoryItem{
		UUID:        uuid.New().String(),
		Description: "Primary Database Server",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "asset-type",
				Value: "hardware",
			},
			{
				Name:  "asset-tag",
				Value: "DB-SRV-001",
			},
			{
				Name:  "location",
				Value: "Data Center A",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/asset-management/DB-SRV-001",
				MediaType: "application/json",
				Text:      "Asset Management Record",
			},
		},
		ResponsibleParties: &[]oscalTypes_1_1_3.ResponsibleParty{
			{
				RoleId:     "asset-manager",
				PartyUuids: []string{"org-1"},
			},
			{
				RoleId:     "system-administrator",
				PartyUuids: []string{"admin-1"},
			},
		},
		ImplementedComponents: &[]oscalTypes_1_1_3.ImplementedComponent{
			{
				ComponentUuid: uuid.New().String(),
				Remarks:       "Database management system running on this server",
			},
		},
		Remarks: "Critical database server hosting production data",
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/inventory-items", ssp.UUID), newInventoryItem)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createInventoryResponse handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]
	err = json.Unmarshal(resp.Body.Bytes(), &createInventoryResponse)
	suite.NoError(err)
	suite.Equal("Primary Database Server", createInventoryResponse.Data.Description)
	suite.Equal("Critical database server hosting production data", createInventoryResponse.Data.Remarks)

	inventoryID := createInventoryResponse.Data.UUID

	// Test UPDATE inventory item
	updatedInventoryItem := oscalTypes_1_1_3.InventoryItem{
		UUID:        inventoryID,
		Description: "Enhanced Primary Database Server",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "asset-type",
				Value: "hardware",
			},
			{
				Name:  "asset-tag",
				Value: "DB-SRV-001",
			},
			{
				Name:  "location",
				Value: "Data Center A - Rack 7",
			},
			{
				Name:  "maintenance-status",
				Value: "up-to-date",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/asset-management/DB-SRV-001",
				MediaType: "application/json",
				Text:      "Asset Management Record",
			},
			{
				Href:      "https://example.com/monitoring/DB-SRV-001",
				MediaType: "application/json",
				Text:      "Server Monitoring Dashboard",
			},
		},
		ResponsibleParties: &[]oscalTypes_1_1_3.ResponsibleParty{
			{
				RoleId:     "asset-manager",
				PartyUuids: []string{"org-1"},
			},
			{
				RoleId:     "system-administrator",
				PartyUuids: []string{"admin-1"},
			},
			{
				RoleId:     "database-administrator",
				PartyUuids: []string{"dba-1"},
			},
		},
		ImplementedComponents: &[]oscalTypes_1_1_3.ImplementedComponent{
			{
				ComponentUuid: uuid.New().String(),
				Remarks:       "Enhanced database management system with high availability",
			},
		},
		Remarks: "Enhanced critical database server with improved monitoring and high availability",
	}

	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/inventory-items/%s", ssp.UUID, inventoryID), updatedInventoryItem)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var updateInventoryResponse handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]
	err = json.Unmarshal(resp.Body.Bytes(), &updateInventoryResponse)
	suite.NoError(err)
	suite.Equal("Enhanced Primary Database Server", updateInventoryResponse.Data.Description)
	suite.Equal("Enhanced critical database server with improved monitoring and high availability", updateInventoryResponse.Data.Remarks)

	// Verify props
	suite.Require().NotNil(updateInventoryResponse.Data.Props)
	suite.Len(*updateInventoryResponse.Data.Props, 4)
	suite.Equal("location", (*updateInventoryResponse.Data.Props)[2].Name)
	suite.Equal("Data Center A - Rack 7", (*updateInventoryResponse.Data.Props)[2].Value)
	suite.Equal("maintenance-status", (*updateInventoryResponse.Data.Props)[3].Name)
	suite.Equal("up-to-date", (*updateInventoryResponse.Data.Props)[3].Value)

	// Test DELETE inventory item
	req = suite.createRequest("DELETE", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/inventory-items/%s", ssp.UUID, inventoryID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify inventory item is deleted
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/inventory-items", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var finalInventoryResponse handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]
	err = json.Unmarshal(resp.Body.Bytes(), &finalInventoryResponse)
	suite.NoError(err)

	// Should not contain the deleted inventory item
	for _, item := range finalInventoryResponse.Data {
		suite.NotEqual(inventoryID, item.UUID)
	}
}

// Test system implementation leveraged authorizations CRUD operations
func (suite *SystemSecurityPlanApiIntegrationSuite) TestSystemImplementationLeveragedAuthorizationsCRUD() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP first
	ssp := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Test GET leveraged authorizations
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/leveraged-authorizations", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var getLeveragedAuthsResponse handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]
	err = json.Unmarshal(resp.Body.Bytes(), &getLeveragedAuthsResponse)
	suite.NoError(err)

	// Test CREATE leveraged authorization
	newLeveragedAuth := oscalTypes_1_1_3.LeveragedAuthorization{
		UUID:  uuid.New().String(),
		Title: "AWS Cloud Platform Authorization",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "authorization-type",
				Value: "cloud-platform",
			},
			{
				Name:  "authorization-level",
				Value: "fedramp-high",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/aws-fedramp-authorization",
				MediaType: "application/pdf",
				Text:      "AWS FedRAMP Authorization Package",
			},
		},
		PartyUuid:      uuid.New().String(),
		DateAuthorized: time.Now().Format("2006-01-02"),
		Remarks:        "Leveraged authorization for AWS cloud platform services under FedRAMP High",
	}

	req = suite.createRequest("POST", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/leveraged-authorizations", ssp.UUID), newLeveragedAuth)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var createLeveragedAuthResponse handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]
	err = json.Unmarshal(resp.Body.Bytes(), &createLeveragedAuthResponse)
	suite.NoError(err)
	suite.Equal("AWS Cloud Platform Authorization", createLeveragedAuthResponse.Data.Title)
	suite.Equal("Leveraged authorization for AWS cloud platform services under FedRAMP High", createLeveragedAuthResponse.Data.Remarks)

	authID := createLeveragedAuthResponse.Data.UUID

	// Test UPDATE leveraged authorization
	updatedLeveragedAuth := oscalTypes_1_1_3.LeveragedAuthorization{
		UUID:  authID,
		Title: "Enhanced AWS Cloud Platform Authorization",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Name:  "authorization-type",
				Value: "cloud-platform",
			},
			{
				Name:  "authorization-level",
				Value: "fedramp-high",
			},
			{
				Name:  "review-status",
				Value: "reviewed",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "https://example.com/aws-fedramp-authorization",
				MediaType: "application/pdf",
				Text:      "AWS FedRAMP Authorization Package",
			},
			{
				Href:      "https://example.com/internal-review-report",
				MediaType: "application/pdf",
				Text:      "Internal Security Review Report",
			},
		},
		PartyUuid:      uuid.New().String(),
		DateAuthorized: time.Now().Format("2006-01-02"),
		Remarks:        "Enhanced leveraged authorization for AWS cloud platform services with additional security controls and regular reviews",
	}

	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/leveraged-authorizations/%s", ssp.UUID, authID), updatedLeveragedAuth)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var updateLeveragedAuthResponse handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]
	err = json.Unmarshal(resp.Body.Bytes(), &updateLeveragedAuthResponse)
	suite.NoError(err)
	suite.Equal("Enhanced AWS Cloud Platform Authorization", updateLeveragedAuthResponse.Data.Title)
	suite.Equal("Enhanced leveraged authorization for AWS cloud platform services with additional security controls and regular reviews", updateLeveragedAuthResponse.Data.Remarks)

	// Verify props
	suite.Require().NotNil(updateLeveragedAuthResponse.Data.Props)
	suite.Len(*updateLeveragedAuthResponse.Data.Props, 3)
	suite.Equal("review-status", (*updateLeveragedAuthResponse.Data.Props)[2].Name)
	suite.Equal("reviewed", (*updateLeveragedAuthResponse.Data.Props)[2].Value)

	// Test DELETE leveraged authorization
	req = suite.createRequest("DELETE", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/leveraged-authorizations/%s", ssp.UUID, authID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify leveraged authorization is deleted
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/leveraged-authorizations", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var finalLeveragedAuthsResponse handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]
	err = json.Unmarshal(resp.Body.Bytes(), &finalLeveragedAuthsResponse)
	suite.NoError(err)

	// Should not contain the deleted leveraged authorization
	for _, auth := range finalLeveragedAuthsResponse.Data {
		suite.NotEqual(authID, auth.UUID)
	}
}

func TestSystemSecurityPlanApiIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SystemSecurityPlanApiIntegrationSuite))
}

// Test creating a Network Architecture diagram
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateNetworkArchitectureDiagram() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP with a NetworkArchitecture present
	ssp := suite.createBasicSSP()
	na := oscalTypes_1_1_3.NetworkArchitecture{
		Description: "Test NA",
	}
	ssp.SystemCharacteristics.NetworkArchitecture = &na

	// Create the SSP
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create a new diagram under network architecture
	diagram := oscalTypes_1_1_3.Diagram{
		UUID:        uuid.New().String(),
		Description: "Network diagram 1",
		Caption:     "NA Diagram",
	}

	createReq := suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams", ssp.UUID), diagram)
	createResp := httptest.NewRecorder()
	server.E().ServeHTTP(createResp, createReq)
	suite.Equal(http.StatusCreated, createResp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
	err = json.Unmarshal(createResp.Body.Bytes(), &createResponse)
	suite.Require().NoError(err)
	suite.Equal(diagram.UUID, createResponse.Data.UUID)
	suite.Equal("Network diagram 1", createResponse.Data.Description)
	suite.Equal("NA Diagram", createResponse.Data.Caption)

	// Fetch NA and verify the diagram is listed
	getReq := suite.createRequest(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture", ssp.UUID), nil)
	getResp := httptest.NewRecorder()
	server.E().ServeHTTP(getResp, getReq)
	suite.Equal(http.StatusOK, getResp.Code)

	var naResponse handler.GenericDataResponse[*oscalTypes_1_1_3.NetworkArchitecture]
	err = json.Unmarshal(getResp.Body.Bytes(), &naResponse)
	suite.Require().NoError(err)
	suite.Require().NotNil(naResponse.Data)
	suite.Require().NotNil(naResponse.Data.Diagrams)
	suite.Require().GreaterOrEqual(len(*naResponse.Data.Diagrams), 1)

	// Ensure one of the diagrams matches the created one
	found := false
	for _, d := range *naResponse.Data.Diagrams {
		if d.UUID == diagram.UUID {
			found = true
			break
		}
	}
	suite.True(found, "created diagram should be present in network architecture")
}

// Test creating a Data Flow diagram
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateDataFlowDiagram() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP with a DataFlow present
	ssp := suite.createBasicSSP()
	df := oscalTypes_1_1_3.DataFlow{
		Description: "Test DF",
	}
	ssp.SystemCharacteristics.DataFlow = &df

	// Create the SSP
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create a new diagram under data flow
	diagram := oscalTypes_1_1_3.Diagram{
		UUID:        uuid.New().String(),
		Description: "Data flow diagram 1",
		Caption:     "DF Diagram",
	}

	createReq := suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams", ssp.UUID), diagram)
	createResp := httptest.NewRecorder()
	server.E().ServeHTTP(createResp, createReq)
	suite.Equal(http.StatusCreated, createResp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
	err = json.Unmarshal(createResp.Body.Bytes(), &createResponse)
	suite.Require().NoError(err)
	suite.Equal(diagram.UUID, createResponse.Data.UUID)
	suite.Equal("Data flow diagram 1", createResponse.Data.Description)
	suite.Equal("DF Diagram", createResponse.Data.Caption)

	// Fetch Data Flow and verify the diagram is listed
	getReq := suite.createRequest(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow", ssp.UUID), nil)
	getResp := httptest.NewRecorder()
	server.E().ServeHTTP(getResp, getReq)
	suite.Equal(http.StatusOK, getResp.Code)

	var dfResponse handler.GenericDataResponse[*oscalTypes_1_1_3.DataFlow]
	err = json.Unmarshal(getResp.Body.Bytes(), &dfResponse)
	suite.Require().NoError(err)
	suite.Require().NotNil(dfResponse.Data)
	suite.Require().NotNil(dfResponse.Data.Diagrams)
	suite.Require().GreaterOrEqual(len(*dfResponse.Data.Diagrams), 1)

	found := false
	for _, d := range *dfResponse.Data.Diagrams {
		if d.UUID == diagram.UUID {
			found = true
			break
		}
	}
	suite.True(found, "created diagram should be present in data flow")
}

// Test creating an Authorization Boundary diagram
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateAuthorizationBoundaryDiagram() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP with an AuthorizationBoundary present
	ssp := suite.createBasicSSP()
	ab := oscalTypes_1_1_3.AuthorizationBoundary{
		Description: "Test AB",
	}
	ssp.SystemCharacteristics.AuthorizationBoundary = ab

	// Create the SSP
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Create a new diagram under authorization boundary
	diagram := oscalTypes_1_1_3.Diagram{
		UUID:        uuid.New().String(),
		Description: "Authorization boundary diagram 1",
		Caption:     "AB Diagram",
	}

	createReq := suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary/diagrams", ssp.UUID), diagram)
	createResp := httptest.NewRecorder()
	server.E().ServeHTTP(createResp, createReq)
	suite.Equal(http.StatusCreated, createResp.Code)

	var createResponse handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
	err = json.Unmarshal(createResp.Body.Bytes(), &createResponse)
	suite.Require().NoError(err)
	suite.Equal(diagram.UUID, createResponse.Data.UUID)
	suite.Equal("Authorization boundary diagram 1", createResponse.Data.Description)
	suite.Equal("AB Diagram", createResponse.Data.Caption)

	// Fetch Authorization Boundary and verify the diagram is listed
	getReq := suite.createRequest(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary", ssp.UUID), nil)
	getResp := httptest.NewRecorder()
	server.E().ServeHTTP(getResp, getReq)
	suite.Equal(http.StatusOK, getResp.Code)

	var abResponse handler.GenericDataResponse[*oscalTypes_1_1_3.AuthorizationBoundary]
	err = json.Unmarshal(getResp.Body.Bytes(), &abResponse)
	suite.Require().NoError(err)
	suite.Require().NotNil(abResponse.Data)
	suite.Require().NotNil(abResponse.Data.Diagrams)
	suite.Require().GreaterOrEqual(len(*abResponse.Data.Diagrams), 1)

	found := false
	for _, d := range *abResponse.Data.Diagrams {
		if d.UUID == diagram.UUID {
			found = true
			break
		}
	}
	suite.True(found, "created diagram should be present in authorization boundary")
}

// Negative: Network Architecture missing, invalid IDs and invalid body
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateNetworkArchitectureDiagram_Negative() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// 1) Invalid SSP ID in path
	badDiagram := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "bad"}
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans/not-a-uuid/system-characteristics/network-architecture/diagrams", badDiagram)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// 2) Missing Network Architecture -> 404
	ssp := suite.createBasicSSP()
	ssp.SystemCharacteristics.NetworkArchitecture = nil
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Attempt to create diagram when NA is missing
	diagram := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "NA diag"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams", ssp.UUID), diagram)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNotFound, resp.Code)

	// 3) Invalid/Missing diagram UUID -> 400
	// Recreate SSP with NA present
	err = suite.Migrator.Refresh()
	suite.Require().NoError(err)
	ssp2 := suite.createBasicSSP()
	na := oscalTypes_1_1_3.NetworkArchitecture{Description: "present"}
	ssp2.SystemCharacteristics.NetworkArchitecture = &na
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp2)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Missing UUID
	missingUUID := oscalTypes_1_1_3.Diagram{Description: "no uuid"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams", ssp2.UUID), missingUUID)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// Invalid UUID format
	invalidUUID := oscalTypes_1_1_3.Diagram{UUID: "not-a-uuid", Description: "bad uuid"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams", ssp2.UUID), invalidUUID)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)
}

// Negative: Data Flow missing, invalid IDs and invalid body
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateDataFlowDiagram_Negative() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// 1) Invalid SSP ID in path
	badDiagram := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "bad"}
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans/not-a-uuid/system-characteristics/data-flow/diagrams", badDiagram)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// 2) Missing Data Flow -> 404
	ssp := suite.createBasicSSP()
	ssp.SystemCharacteristics.DataFlow = nil
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	diagram := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "DF diag"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams", ssp.UUID), diagram)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNotFound, resp.Code)

	// 3) Invalid/Missing diagram UUID -> 400
	// Recreate SSP with DF present
	err = suite.Migrator.Refresh()
	suite.Require().NoError(err)
	ssp2 := suite.createBasicSSP()
	df := oscalTypes_1_1_3.DataFlow{Description: "present"}
	ssp2.SystemCharacteristics.DataFlow = &df
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp2)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Missing UUID
	missingUUID := oscalTypes_1_1_3.Diagram{Description: "no uuid"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams", ssp2.UUID), missingUUID)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// Invalid UUID format
	invalidUUID := oscalTypes_1_1_3.Diagram{UUID: "not-a-uuid", Description: "bad uuid"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams", ssp2.UUID), invalidUUID)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)
}

// Negative: Authorization Boundary invalid IDs and invalid body
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateAuthorizationBoundaryDiagram_Negative() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// 1) Invalid SSP ID in path
	badDiagram := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "bad"}
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans/not-a-uuid/system-characteristics/authorization-boundary/diagrams", badDiagram)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// 2) Invalid/Missing diagram UUID -> 400 (AB always present in model)
	ssp := suite.createBasicSSP()
	ab := oscalTypes_1_1_3.AuthorizationBoundary{Description: "present"}
	ssp.SystemCharacteristics.AuthorizationBoundary = ab
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	// Missing UUID
	missingUUID := oscalTypes_1_1_3.Diagram{Description: "no uuid"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary/diagrams", ssp.UUID), missingUUID)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// Invalid UUID format
	invalidUUID := oscalTypes_1_1_3.Diagram{UUID: "not-a-uuid", Description: "bad uuid"}
	req = suite.createRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary/diagrams", ssp.UUID), invalidUUID)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)
}

// Delete tests
func (suite *SystemSecurityPlanApiIntegrationSuite) TestDeleteNetworkArchitectureDiagram() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP with NA and one diagram
	ssp := suite.createBasicSSP()
	na := oscalTypes_1_1_3.NetworkArchitecture{Description: "NA"}
	ssp.SystemCharacteristics.NetworkArchitecture = &na
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	diag := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "to delete"}
	creq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams", ssp.UUID), diag)
	cresp := httptest.NewRecorder()
	server.E().ServeHTTP(cresp, creq)
	suite.Equal(http.StatusCreated, cresp.Code)

	// Delete
	dreq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams/%s", ssp.UUID, diag.UUID), nil)
	dresp := httptest.NewRecorder()
	server.E().ServeHTTP(dresp, dreq)
	suite.Equal(http.StatusNoContent, dresp.Code)

	// Verify gone
	greq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture", ssp.UUID), nil)
	gresp := httptest.NewRecorder()
	server.E().ServeHTTP(gresp, greq)
	suite.Equal(http.StatusOK, gresp.Code)

	var got handler.GenericDataResponse[*oscalTypes_1_1_3.NetworkArchitecture]
	err = json.Unmarshal(gresp.Body.Bytes(), &got)
	suite.Require().NoError(err)
	if got.Data.Diagrams != nil {
		for _, d := range *got.Data.Diagrams {
			suite.NotEqual(diag.UUID, d.UUID, "diagram should be deleted")
		}
	}
}

func (suite *SystemSecurityPlanApiIntegrationSuite) TestDeleteDataFlowDiagram() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP with DF and one diagram
	ssp := suite.createBasicSSP()
	df := oscalTypes_1_1_3.DataFlow{Description: "DF"}
	ssp.SystemCharacteristics.DataFlow = &df
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	diag := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "to delete"}
	creq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams", ssp.UUID), diag)
	cresp := httptest.NewRecorder()
	server.E().ServeHTTP(cresp, creq)
	suite.Equal(http.StatusCreated, cresp.Code)

	// Delete
	dreq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams/%s", ssp.UUID, diag.UUID), nil)
	dresp := httptest.NewRecorder()
	server.E().ServeHTTP(dresp, dreq)
	suite.Equal(http.StatusNoContent, dresp.Code)

	// Verify gone
	greq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow", ssp.UUID), nil)
	gresp := httptest.NewRecorder()
	server.E().ServeHTTP(gresp, greq)
	suite.Equal(http.StatusOK, gresp.Code)

	var got handler.GenericDataResponse[*oscalTypes_1_1_3.DataFlow]
	err = json.Unmarshal(gresp.Body.Bytes(), &got)
	suite.Require().NoError(err)
	if got.Data.Diagrams != nil {
		for _, d := range *got.Data.Diagrams {
			suite.NotEqual(diag.UUID, d.UUID, "diagram should be deleted")
		}
	}
}

func (suite *SystemSecurityPlanApiIntegrationSuite) TestDeleteAuthorizationBoundaryDiagram() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create SSP with AB and one diagram
	ssp := suite.createBasicSSP()
	ab := oscalTypes_1_1_3.AuthorizationBoundary{Description: "AB"}
	ssp.SystemCharacteristics.AuthorizationBoundary = ab
	req := suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	diag := oscalTypes_1_1_3.Diagram{UUID: uuid.New().String(), Description: "to delete"}
	creq := suite.createRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary/diagrams", ssp.UUID), diag)
	cresp := httptest.NewRecorder()
	server.E().ServeHTTP(cresp, creq)
	suite.Equal(http.StatusCreated, cresp.Code)

	// Delete
	dreq := suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary/diagrams/%s", ssp.UUID, diag.UUID), nil)
	dresp := httptest.NewRecorder()
	server.E().ServeHTTP(dresp, dreq)
	suite.Equal(http.StatusNoContent, dresp.Code)

	// Verify gone
	greq := suite.createRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary", ssp.UUID), nil)
	gresp := httptest.NewRecorder()
	server.E().ServeHTTP(gresp, greq)
	suite.Equal(http.StatusOK, gresp.Code)

	var got handler.GenericDataResponse[*oscalTypes_1_1_3.AuthorizationBoundary]
	err = json.Unmarshal(gresp.Body.Bytes(), &got)
	suite.Require().NoError(err)
	if got.Data.Diagrams != nil {
		for _, d := range *got.Data.Diagrams {
			suite.NotEqual(diag.UUID, d.UUID, "diagram should be deleted")
		}
	}
}

// Negative deletes
func (suite *SystemSecurityPlanApiIntegrationSuite) TestDeleteNetworkArchitectureDiagram_Negative() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// invalid SSP id
	req := suite.createRequest(http.MethodDelete, "/api/oscal/system-security-plans/not-a-uuid/system-characteristics/network-architecture/diagrams/not-a-uuid", nil)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// valid SSP with NA, invalid diagram id
	ssp := suite.createBasicSSP()
	na := oscalTypes_1_1_3.NetworkArchitecture{Description: "NA"}
	ssp.SystemCharacteristics.NetworkArchitecture = &na
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams/not-a-uuid", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// non-existent diagram id
	req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/network-architecture/diagrams/%s", ssp.UUID, uuid.New().String()), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNotFound, resp.Code)
}

func (suite *SystemSecurityPlanApiIntegrationSuite) TestDeleteDataFlowDiagram_Negative() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// invalid SSP id
	req := suite.createRequest(http.MethodDelete, "/api/oscal/system-security-plans/not-a-uuid/system-characteristics/data-flow/diagrams/not-a-uuid", nil)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// valid SSP with DF, invalid diagram id
	ssp := suite.createBasicSSP()
	df := oscalTypes_1_1_3.DataFlow{Description: "DF"}
	ssp.SystemCharacteristics.DataFlow = &df
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams/not-a-uuid", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// non-existent diagram id
	req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/data-flow/diagrams/%s", ssp.UUID, uuid.New().String()), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNotFound, resp.Code)
}

func (suite *SystemSecurityPlanApiIntegrationSuite) TestDeleteAuthorizationBoundaryDiagram_Negative() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// invalid SSP id
	req := suite.createRequest(http.MethodDelete, "/api/oscal/system-security-plans/not-a-uuid/system-characteristics/authorization-boundary/diagrams/not-a-uuid", nil)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// valid SSP with AB, invalid diagram id
	ssp := suite.createBasicSSP()
	ab := oscalTypes_1_1_3.AuthorizationBoundary{Description: "AB"}
	ssp.SystemCharacteristics.AuthorizationBoundary = ab
	req = suite.createRequest(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary/diagrams/not-a-uuid", ssp.UUID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusBadRequest, resp.Code)

	// non-existent diagram id
	req = suite.createRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/system-characteristics/authorization-boundary/diagrams/%s", ssp.UUID, uuid.New().String()), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNotFound, resp.Code)
}

func (suite *SystemSecurityPlanApiIntegrationSuite) TestAttachProfile() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// 1. Setup data: Catalog -> Controls -> Profile
	catalog := &relational.Catalog{
		Metadata: relational.Metadata{Title: "Test Catalog"},
	}
	suite.Require().NoError(suite.DB.Create(catalog).Error)

	control1 := relational.Control{
		ID:        "ac-1",
		CatalogID: *catalog.UUIDModel.ID,
		Title:     "Access Control 1",
	}
	control2 := relational.Control{
		ID:        "ac-2",
		CatalogID: *catalog.UUIDModel.ID,
		Title:     "Access Control 2",
	}
	suite.Require().NoError(suite.DB.Create(&control1).Error)
	suite.Require().NoError(suite.DB.Create(&control2).Error)

	profile := &relational.Profile{
		Metadata: relational.Metadata{Title: "Test Profile"},
		Controls: []relational.Control{control1, control2},
	}
	suite.Require().NoError(suite.DB.Create(profile).Error)

	// 2. Create SSP
	sspData := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", sspData)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var sspResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
	suite.Require().NoError(json.Unmarshal(resp.Body.Bytes(), &sspResponse))
	sspID := sspResponse.Data.UUID

	// 3. Attach Profile to SSP
	attachInput := struct {
		ProfileID string `json:"profileId"`
	}{
		ProfileID: profile.UUIDModel.ID.String(),
	}

	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/profile", sspID), attachInput)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)

	suite.Equal(http.StatusOK, resp.Code)

	// 4. Verify ImplementedRequirements were automatically created for the profile controls
	// Note: createBasicSSP already creates ac-1, so only ac-2 should be newly created.
	// Total requirements should be 2: ac-1 and ac-2.
	var sspReloaded relational.SystemSecurityPlan
	err = suite.DB.Preload("ControlImplementation.ImplementedRequirements").First(&sspReloaded, "id = ?", sspID).Error
	suite.Require().NoError(err)

	suite.Require().NotNil(sspReloaded.ControlImplementation.ID)
	suite.Require().Len(sspReloaded.ControlImplementation.ImplementedRequirements, 2)

	foundAC1, foundAC2 := false, false
	for _, req := range sspReloaded.ControlImplementation.ImplementedRequirements {
		if req.ControlId == "ac-1" {
			foundAC1 = true
		}
		if req.ControlId == "ac-2" {
			foundAC2 = true
		}
	}
	suite.True(foundAC1, "ac-1 requirement should be present")
	suite.True(foundAC2, "ac-2 requirement should be created")
}

func (suite *SystemSecurityPlanApiIntegrationSuite) TestGetImplementedRequirementsFiltering() {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// 1. Setup data: Catalog -> Controls -> Two Profiles
	catalog := &relational.Catalog{
		Metadata: relational.Metadata{Title: "Test Catalog"},
	}
	suite.Require().NoError(suite.DB.Create(catalog).Error)

	control1 := relational.Control{ID: "C1", CatalogID: *catalog.UUIDModel.ID, Title: "C1"}
	control2 := relational.Control{ID: "C2", CatalogID: *catalog.UUIDModel.ID, Title: "C2"}
	control3 := relational.Control{ID: "C3", CatalogID: *catalog.UUIDModel.ID, Title: "C3"}
	suite.Require().NoError(suite.DB.Create(&control1).Error)
	suite.Require().NoError(suite.DB.Create(&control2).Error)
	suite.Require().NoError(suite.DB.Create(&control3).Error)

	profileA := &relational.Profile{
		Metadata: relational.Metadata{Title: "Profile A"},
		Controls: []relational.Control{control1, control2},
	}
	profileB := &relational.Profile{
		Metadata: relational.Metadata{Title: "Profile B"},
		Controls: []relational.Control{control3},
	}
	suite.Require().NoError(suite.DB.Create(profileA).Error)
	suite.Require().NoError(suite.DB.Create(profileB).Error)

	// 2. Create SSP and attach Profile A
	sspData := suite.createBasicSSP()
	req := suite.createRequest("POST", "/api/oscal/system-security-plans", sspData)
	resp := httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusCreated, resp.Code)

	var sspResponse handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
	suite.Require().NoError(json.Unmarshal(resp.Body.Bytes(), &sspResponse))
	sspID := sspResponse.Data.UUID

	// Attach Profile A
	attachInput := struct {
		ProfileID string `json:"profileId"`
	}{ProfileID: profileA.UUIDModel.ID.String()}
	req = suite.createRequest("PUT", fmt.Sprintf("/api/oscal/system-security-plans/%s/profile", sspID), attachInput)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	// 3. Manually create an ImplementedRequirement for C3 (which is NOT in Profile A)
	var ssp relational.SystemSecurityPlan
	suite.Require().NoError(suite.DB.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error)

	c3ReqID := uuid.New()
	c3Req := relational.ImplementedRequirement{
		UUIDModel:               relational.UUIDModel{ID: &c3ReqID},
		ControlImplementationId: *ssp.ControlImplementation.ID,
		ControlId:               "C3",
	}
	suite.Require().NoError(suite.DB.Create(&c3Req).Error)

	// 4. Get ImplementedRequirements and verify filtering
	// Since Profile A is attached, we should only see requirements for C1 and C2, NOT C3.
	req = suite.createRequest("GET", fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", sspID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusOK, resp.Code)

	var requirementsResponse handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirement]
	suite.Require().NoError(json.Unmarshal(resp.Body.Bytes(), &requirementsResponse))

	// Should have C1, C2 from AttachProfile, but C3 should be filtered out because it's not in Profile A
	suite.Require().Len(requirementsResponse.Data, 2)
	for _, req := range requirementsResponse.Data {
		suite.NotEqual("C3", req.ControlId, "C3 should have been filtered out")
	}
}
