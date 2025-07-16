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

	testCases := []struct {
		name           string
		sspID          string
		reqID          string
		expectedStatus int
	}{
		{
			name:           "invalid SSP ID",
			sspID:          "invalid-uuid",
			reqID:          uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid requirement ID",
			sspID:          ssp.UUID,
			reqID:          "invalid-uuid",
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
			sspID:          ssp.UUID,
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

	testCases := []struct {
		name           string
		sspID          string
		reqID          string
		stmtID         string
		expectedStatus int
	}{
		{
			name:           "invalid SSP ID",
			sspID:          "invalid-uuid",
			reqID:          uuid.New().String(),
			stmtID:         uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid requirement ID",
			sspID:          ssp.UUID,
			reqID:          "invalid-uuid",
			stmtID:         uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid statement ID",
			sspID:          ssp.UUID,
			reqID:          uuid.New().String(),
			stmtID:         "invalid-uuid",
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

func TestSystemSecurityPlanApiIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SystemSecurityPlanApiIntegrationSuite))
}
