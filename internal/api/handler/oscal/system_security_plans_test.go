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

// Test creating a statement within an implemented requirement
func (suite *SystemSecurityPlanApiIntegrationSuite) TestCreateImplementedRequirementStatement() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

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
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

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

// Test updating a statement with invalid IDs
func (suite *SystemSecurityPlanApiIntegrationSuite) TestUpdateImplementedRequirementStatementInvalidIDs() {
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

	// Test DELETE component
	req = suite.createRequest("DELETE", fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components/%s", ssp.UUID, componentID), nil)
	resp = httptest.NewRecorder()
	server.E().ServeHTTP(resp, req)
	suite.Equal(http.StatusNoContent, resp.Code)

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
