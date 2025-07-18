// go build:integration
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestUserApi(t *testing.T) {
	suite.Run(t, new(UserApiIntegrationSuite))
}

type UserApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *UserApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config)
}

func (suite *UserApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

func (suite *UserApiIntegrationSuite) TestUserList() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListUsers")
	suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for ListUsers")

	var response GenericDataListResponse[relational.User]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for ListUsers")
	suite.Require().Equal(len(response.Data), 1, "Expected exactly one user in response for ListUsers")
}

func (suite *UserApiIntegrationSuite) TestGetUser() {
	var existingUser relational.User
	err := suite.DB.First(&existingUser).Error
	suite.Require().NoError(err, "Failed to retrieve existing user for GetUser test")
	existingUser.PasswordHash = "" // Clear password hash for response validation

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users/"+existingUser.UUIDModel.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for GetUser")
	suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for GetUser")

	var response GenericDataResponse[relational.User]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for GetUser")
	suite.Require().Equal(existingUser, response.Data, "Expected matching user ID in response for GetUser")
}

func (suite *UserApiIntegrationSuite) TestGetMe() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for GetMe")
	suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for GetMe")

	var response GenericDataResponse[relational.User]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for GetMe")
	suite.Require().Equal(response.Data.Email, "dummy@example.com", "Expected email to match dummy user in GetMe response")
	suite.Require().Equal(response.Data.FirstName, "Dummy", "Expected first name to match dummy user in GetMe response")
	suite.Require().Equal(response.Data.LastName, "User", "Expected last name to match dummy user in GetMe response")
}

func (suite *UserApiIntegrationSuite) TestCreateUser() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	type createUserRequest struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}

	suite.Run("CreateUser", func() {
		newUser := createUserRequest{
			Email:     "newuser@example.com",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		newUserJSON, err := json.Marshal(newUser)
		suite.Require().NoError(err, "Failed to marshal new user request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/users", bytes.NewReader(newUserJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(201, rec.Code, "Expected Created response for CreateUser")
		suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for CreateUser")

		var response GenericDataResponse[relational.User]
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Expected valid JSON response for CreateUser")
		suite.Require().Equal(response.Data.Email, newUser.Email, "Expected email to match new user in CreateUser response")
		suite.Require().Equal(response.Data.FirstName, newUser.FirstName, "Expected first name to match new user in CreateUser response")
		suite.Require().Equal(response.Data.LastName, newUser.LastName, "Expected last name to match new user in CreateUser response")
	})

	suite.Run("CreateUserWithExistingEmail", func() {
		existingUser := createUserRequest{
			Email:     "dummy@example.com",
			Password:  "password123",
			FirstName: "Existing",
			LastName:  "User",
		}

		existingUserJSON, err := json.Marshal(existingUser)
		suite.Require().NoError(err, "Failed to marshal existing user request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/users", bytes.NewReader(existingUserJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(409, rec.Code, "Expected Conflict response for CreateUser with existing email")
		suite.Contains(rec.Body.String(), "email already exists", "Expected error message for existing email in CreateUser response")
	})
}

func (suite *UserApiIntegrationSuite) ModifyUser() {
	var existingUser relational.User
	err := suite.DB.First(&existingUser).Error
	suite.Require().NoError(err, "Failed to retrieve existing user for GetUser test")

	userId := existingUser.UUIDModel.ID.String()

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	type modifyUserRequest struct {
		FirstName    string `json:"firstName,omitempty"`
		LastName     string `json:"lastName,omitempty"`
		IsActive     bool   `json:"isActive,omitempty"`
		IsLocked     bool   `json:"isLocked,omitempty"`
		FailedLogins int    `json:"failedLogins,omitempty"`
	}

	suite.Run("FullPayload", func() {
		suite.Migrator.Refresh()
		modifyRequest := modifyUserRequest{
			FirstName:    "Test",
			LastName:     "Testington",
			IsActive:     false,
			IsLocked:     true,
			FailedLogins: 3,
		}

		modifyRequestJSON, err := json.Marshal(modifyRequest)
		suite.Require().NoError(err, "Failed to marshal modify user request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/api/users/"+userId, bytes.NewReader(modifyRequestJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for ModifyUser with full payload")
		suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for ModifyUser with full payload")

		var response GenericDataResponse[relational.User]
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Expected valid JSON response for ModifyUser with full payload")
		suite.Require().Equal(response.Data.FirstName, modifyRequest.FirstName, "Expected first name to match modified user in ModifyUser response")
		suite.Require().Equal(response.Data.LastName, modifyRequest.LastName, "Expected last name to match modified user in ModifyUser response")
		suite.Require().Equal(response.Data.IsActive, modifyRequest.IsActive, "Expected isActive to match modified user in ModifyUser response")
		suite.Require().Equal(response.Data.IsLocked, modifyRequest.IsLocked, "Expected isLocked to match modified user in ModifyUser response")
		suite.Require().Equal(response.Data.FailedLogins, modifyRequest.FailedLogins, "Expected failed logins to match modified user in ModifyUser response")
	})

	suite.Run("PartialPayload", func() {
		suite.Migrator.Refresh()
		modifyRequest := modifyUserRequest{
			FirstName: "Partial",
		}

		modifyRequestJSON, err := json.Marshal(modifyRequest)
		suite.Require().NoError(err, "Failed to marshal modify user request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/api/users/"+userId, bytes.NewReader(modifyRequestJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for ModifyUser with partial payload")
		suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for ModifyUser with partial payload")

		var response GenericDataResponse[relational.User]
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Expected valid JSON response for ModifyUser with partial payload")
		suite.Require().Equal(response.Data.FirstName, modifyRequest.FirstName, "Expected first name to match modified user in ModifyUser response")
		suite.Require().Equal(response.Data.LastName, existingUser.LastName, "Expected last name to remain unchanged in ModifyUser response")
		suite.Require().Equal(response.Data.IsActive, existingUser.IsActive, "Expected isActive to remain unchanged in ModifyUser response")
		suite.Require().Equal(response.Data.IsLocked, existingUser.IsLocked, "Expected isLocked to remain unchanged in ModifyUser response")
		suite.Require().Equal(response.Data.FailedLogins, existingUser.FailedLogins, "Expected failed logins to remain unchanged in ModifyUser response")
	})

	suite.Run("EmptyPayload", func() {
		suite.Migrator.Refresh()
		modifyRequest := modifyUserRequest{}

		modifyRequestJSON, err := json.Marshal(modifyRequest)
		suite.Require().NoError(err, "Failed to marshal empty modify user request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/api/users/"+userId, bytes.NewReader(modifyRequestJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for ModifyUser with empty payload")
		suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for ModifyUser with empty payload")

		var response GenericDataResponse[relational.User]
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Expected valid JSON response for ModifyUser with empty payload")
		suite.Require().Equal(response.Data.FirstName, existingUser.FirstName, "Expected first name to remain unchanged in ModifyUser response")
		suite.Require().Equal(response.Data.LastName, existingUser.LastName, "Expected last name to remain unchanged in ModifyUser response")
		suite.Require().Equal(response.Data.IsActive, existingUser.IsActive, "Expected isActive to remain unchanged in ModifyUser response")
		suite.Require().Equal(response.Data.IsLocked, existingUser.IsLocked, "Expected isLocked to remain unchanged in ModifyUser response")
		suite.Require().Equal(response.Data.FailedLogins, existingUser.FailedLogins, "Expected failed logins to remain unchanged in ModifyUser response")
	})
}

func (suite *UserApiIntegrationSuite) TestDeleteUser() {
	var existingUser relational.User
	err := suite.DB.First(&existingUser).Error
	suite.Require().NoError(err, "Failed to retrieve existing user for DeleteUser test")

	userId := existingUser.UUIDModel.ID.String()

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/users/"+userId, nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(204, rec.Code, "Expected No Content response for DeleteUser")
	suite.Empty(rec.Body.String(), "Expected empty response body for DeleteUser")

	// Verify user is deleted
	var deletedUser relational.User
	err = suite.DB.First(&deletedUser, existingUser.UUIDModel.ID).Error
	suite.Error(err, "Expected error when retrieving deleted user")
}
