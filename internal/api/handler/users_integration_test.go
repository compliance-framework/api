//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
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
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &APIServices{}
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config, services)
}

func (suite *UserApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

func (suite *UserApiIntegrationSuite) TestUserList() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/users", nil)
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
	req := httptest.NewRequest("GET", "/api/admin/users/"+existingUser.UUIDModel.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for GetUser")
	suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for GetUser")

	var response GenericDataResponse[relational.User]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for GetUser")
	suite.Require().Equal(existingUser.UUIDModel.ID, response.Data.UUIDModel.ID, "Expected matching user ID in response for GetUser")
}

func (suite *UserApiIntegrationSuite) TestGetPublicUser() {
	var existingUser relational.User
	err := suite.DB.First(&existingUser).Error
	suite.Require().NoError(err, "Failed to retrieve existing user for GetPublicUser test")

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users/"+existingUser.UUIDModel.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for GetPublicUser")
	suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for GetPublicUser")

	var response GenericDataResponse[publicUserResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for GetPublicUser")
	suite.Require().Equal(existingUser.UUIDModel.ID.String(), response.Data.ID, "Expected matching user ID in response for GetPublicUser")
	suite.Require().Equal(userDisplayName(existingUser), response.Data.Name, "Expected public user name to match the user's display name")

	blankNameUser := relational.User{
		Email:      "blank-name-user@example.com",
		FirstName:  "",
		LastName:   "",
		AuthMethod: "password",
		IsActive:   true,
		IsLocked:   false,
	}
	suite.Require().NoError(blankNameUser.SetPassword("Pa55w0rd"))
	suite.Require().NoError(suite.DB.Create(&blankNameUser).Error)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/users/"+blankNameUser.UUIDModel.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for GetPublicUser fallback name test")

	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for GetPublicUser fallback name test")
	suite.Require().Equal(blankNameUser.UUIDModel.ID.String(), response.Data.ID, "Expected matching user ID in fallback response")
	suite.Require().Equal(blankNameUser.UUIDModel.ID.String(), response.Data.Name, "Expected public user name to fall back to the user ID when first and last names are empty")
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

func (suite *UserApiIntegrationSuite) TestListSelectableUsers() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	activeBefore := relational.User{
		Email:      "active-before@example.com",
		FirstName:  "Aaron",
		LastName:   "Able",
		AuthMethod: "password",
		IsActive:   true,
		IsLocked:   false,
	}
	suite.Require().NoError(activeBefore.SetPassword("Pa55w0rd"))
	suite.Require().NoError(suite.DB.Create(&activeBefore).Error)

	activeAfter := relational.User{
		Email:      "active-after@example.com",
		FirstName:  "Zara",
		LastName:   "Zulu",
		AuthMethod: "password",
		IsActive:   true,
		IsLocked:   false,
	}
	suite.Require().NoError(activeAfter.SetPassword("Pa55w0rd"))
	suite.Require().NoError(suite.DB.Create(&activeAfter).Error)

	inactiveUser := relational.User{
		Email:      "inactive@example.com",
		FirstName:  "Inactive",
		LastName:   "User",
		AuthMethod: "password",
		IsActive:   false,
		IsLocked:   false,
	}
	suite.Require().NoError(inactiveUser.SetPassword("Pa55w0rd"))
	inactiveID := uuid.New()
	inactiveUser.UUIDModel.ID = &inactiveID
	now := time.Now().UTC()
	suite.Require().NoError(suite.DB.Table(inactiveUser.TableName()).Create(map[string]any{
		"id":            inactiveID,
		"created_at":    now,
		"updated_at":    now,
		"email":         inactiveUser.Email,
		"password_hash": inactiveUser.PasswordHash,
		"first_name":    inactiveUser.FirstName,
		"last_name":     inactiveUser.LastName,
		"is_active":     inactiveUser.IsActive,
		"is_locked":     inactiveUser.IsLocked,
		"auth_method":   inactiveUser.AuthMethod,
	}).Error)

	lockedUser := relational.User{
		Email:      "locked@example.com",
		FirstName:  "Locked",
		LastName:   "User",
		AuthMethod: "password",
		IsActive:   true,
		IsLocked:   true,
	}
	suite.Require().NoError(lockedUser.SetPassword("Pa55w0rd"))
	suite.Require().NoError(suite.DB.Create(&lockedUser).Error)

	fallbackUser := relational.User{
		Email:      "fallback@example.com",
		FirstName:  "",
		LastName:   "",
		AuthMethod: "password",
		IsActive:   true,
		IsLocked:   false,
	}
	suite.Require().NoError(fallbackUser.SetPassword("Pa55w0rd"))
	suite.Require().NoError(suite.DB.Create(&fallbackUser).Error)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users/select", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListSelectableUsers")
	suite.NotEmpty(rec.Body.String(), "Expected non-empty response body for ListSelectableUsers")

	var response GenericDataListResponse[selectableUserResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for ListSelectableUsers")
	suite.Require().NotEmpty(response.Data, "Expected at least one selectable user")

	first := response.Data[0]
	suite.Require().NotEmpty(first.ID, "Expected selectable user response to include an id")
	suite.Require().NotEmpty(first.DisplayName, "Expected selectable user response to include a display name")

	for _, user := range response.Data {
		suite.NotEqual(inactiveUser.UUIDModel.ID.String(), user.ID, "Inactive users should not be returned")
		suite.NotEqual(lockedUser.UUIDModel.ID.String(), user.ID, "Locked users should not be returned")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/users/select?search=dummy", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for filtered ListSelectableUsers")

	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for filtered ListSelectableUsers")
	suite.Require().NotEmpty(response.Data, "Expected filtered ListSelectableUsers to return at least one user")
	for _, user := range response.Data {
		suite.Contains(strings.ToLower(user.DisplayName), "dummy", "Expected filtered selectable users to match the search term")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/users/select", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for selectable users fallback test")

	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for selectable users fallback test")
	suite.Require().NotEmpty(response.Data, "Expected selectable users fallback test to return at least one user")

	foundFallback := false
	for _, user := range response.Data {
		if user.ID == fallbackUser.UUIDModel.ID.String() {
			foundFallback = true
			suite.Equal(fallbackUser.UUIDModel.ID.String(), user.DisplayName, "Expected fallback display name to use the user ID when first and last name are empty")
		}
	}
	suite.True(foundFallback, "Expected selectable users response to include the fallback user")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/users/select?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for selectable users limit test")

	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for selectable users limit test")
	suite.Require().Len(response.Data, 1, "Expected limit=1 to return a single user")
	firstPageUserID := response.Data[0].ID

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/users/select?limit=1&offset=1", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for selectable users offset test")

	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Expected valid JSON response for selectable users offset test")
	suite.Require().Len(response.Data, 1, "Expected limit=1&offset=1 to return a single user")
	suite.NotEqual(firstPageUserID, response.Data[0].ID, "Expected the offset page to return a different user than the first page")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/users/select?limit=0", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(400, rec.Code, "Expected bad request response for invalid limit")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/users/select?offset=-1", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(400, rec.Code, "Expected bad request response for invalid offset")
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
		req := httptest.NewRequest("POST", "/api/admin/users", bytes.NewReader(newUserJSON))
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
		req := httptest.NewRequest("POST", "/api/admin/users", bytes.NewReader(existingUserJSON))
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
		req := httptest.NewRequest("PUT", "/api/admin/users/"+userId, bytes.NewReader(modifyRequestJSON))
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
		req := httptest.NewRequest("PUT", "/api/admin/users/"+userId, bytes.NewReader(modifyRequestJSON))
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
		req := httptest.NewRequest("PUT", "/api/admin/users/"+userId, bytes.NewReader(modifyRequestJSON))
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
	req := httptest.NewRequest("DELETE", "/api/admin/users/"+userId, nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(204, rec.Code, "Expected No Content response for DeleteUser")
	suite.Empty(rec.Body.String(), "Expected empty response body for DeleteUser")

	// Verify user is deleted
	var deletedUser relational.User
	err = suite.DB.First(&deletedUser, existingUser.UUIDModel.ID).Error
	suite.Error(err, "Expected error when retrieving deleted user")
}

func (suite *UserApiIntegrationSuite) TestChangeLoggedInUserPassword() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	type changePasswordRequest struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	suite.Run("ChangePasswordSuccess", func() {
		suite.Migrator.Refresh()
		payload := changePasswordRequest{
			OldPassword: "Pa55w0rd",
			NewPassword: "NewPa55w0rd",
		}

		payloadJSON, err := json.Marshal(payload)
		suite.Require().NoError(err, "Failed to marshal change password request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/users/me/change-password", bytes.NewReader(payloadJSON))
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(204, rec.Code, "Expected No Content response for ChangeLoggedInUserPassword")
		suite.Empty(rec.Body.String(), "Expected empty response body for ChangeLoggedInUserPassword")

		var updatedUser relational.User
		err = suite.DB.Where("email = ?", "dummy@example.com").First(&updatedUser).Error
		suite.Require().NoError(err, "Failed to retrieve updated user after password change")

		suite.True(updatedUser.CheckPassword("NewPa55w0rd"), "Expected password to be updated successfully")
	})

	suite.Run("ChangePasswordInvalidOldPassword", func() {
		suite.Migrator.Refresh()
		payload := changePasswordRequest{
			OldPassword: "WrongPa55w0rd",
			NewPassword: "NewPa55w0rd",
		}

		payloadJSON, err := json.Marshal(payload)
		suite.Require().NoError(err, "Failed to marshal change password request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/users/me/change-password", bytes.NewReader(payloadJSON))
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(400, rec.Code, "Expected Bad Request response for ChangeLoggedInUserPassword with invalid old password")
		suite.Contains(rec.Body.String(), "old password does not match", "Expected error message for invalid old password in ChangeLoggedInUserPassword response")
	})
}

func (suite *UserApiIntegrationSuite) TestChangePassword() {
	var existingUser relational.User
	err := suite.DB.First(&existingUser).Error
	suite.Require().NoError(err, "Failed to retrieve existing user for ChangePassword test")
	userId := existingUser.UUIDModel.ID.String()

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	type changePasswordRequest struct {
		NewPassword string `json:"newPassword"`
	}

	suite.Run("ChangePasswordSuccess", func() {
		payload := changePasswordRequest{
			NewPassword: "NewPa55w0rd",
		}
		payloadJSON, err := json.Marshal(payload)
		suite.Require().NoError(err, "Failed to marshal change password request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/users/"+userId+"/change-password", bytes.NewReader(payloadJSON))
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(204, rec.Code, "Expected No Content response for ChangePassword")
		suite.Empty(rec.Body.String(), "Expected empty response body for ChangePassword")

		var updatedUser relational.User
		err = suite.DB.Where("id = ?", userId).First(&updatedUser).Error
		suite.Require().NoError(err, "Failed to retrieve updated user after password change")

		suite.True(updatedUser.CheckPassword("NewPa55w0rd"), "Expected password to be updated successfully")
	})
}

func (suite *UserApiIntegrationSuite) TestSubscriptions() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	suite.Run("GetSubscriptions", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/users/me/subscriptions", nil)
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for GetSubscriptions")

		var response struct {
			Data struct {
				Subscribed                  bool                `json:"subscribed"`
				TaskDailyDigestSubscribed   bool                `json:"taskDailyDigestSubscribed"`
				RiskNotificationsSubscribed bool                `json:"riskNotificationsSubscribed"`
				Notifications               map[string][]string `json:"notifications"`
			} `json:"data"`
		}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Failed to unmarshal GetSubscriptions response")

		// The default should be false for new users
		suite.False(response.Data.Subscribed, "Expected default digest subscription to be false")
		suite.False(response.Data.TaskDailyDigestSubscribed, "Expected task daily digest subscription to default to false")
		suite.True(response.Data.RiskNotificationsSubscribed, "Expected risk notifications subscription to default to true")
		suite.Empty(response.Data.Notifications, "Expected notifications map to default to empty")
	})

	suite.Run("UpdateSubscriptions", func() {
		// Test subscribing to digest
		payload := map[string]interface{}{
			"subscribed":                  true,
			"taskDailyDigestSubscribed":   true,
			"riskNotificationsSubscribed": false,
			"notifications": map[string][]string{
				notification.NotificationTypeTaskAvailable: {"email", "slack", "email"},
			},
		}
		payloadJSON, err := json.Marshal(payload)
		suite.Require().NoError(err, "Failed to marshal update subscriptions request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/api/users/me/subscriptions", bytes.NewReader(payloadJSON))
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for UpdateSubscriptions")

		var response struct {
			Data struct {
				Subscribed                  bool                `json:"subscribed"`
				TaskDailyDigestSubscribed   bool                `json:"taskDailyDigestSubscribed"`
				RiskNotificationsSubscribed bool                `json:"riskNotificationsSubscribed"`
				Notifications               map[string][]string `json:"notifications"`
			} `json:"data"`
		}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Failed to unmarshal UpdateSubscriptions response")

		suite.True(response.Data.Subscribed, "Expected digest subscription to be updated to true")
		suite.True(response.Data.TaskDailyDigestSubscribed, "Expected task daily digest subscription to be updated to true")
		suite.False(response.Data.RiskNotificationsSubscribed, "Expected risk notifications subscription to be updated to false")
		suite.Equal([]string{"email", "slack"}, response.Data.Notifications[notification.NotificationTypeTaskAvailable], "Expected notifications to be normalized and persisted")

		// Test unsubscribing from digest
		payload = map[string]interface{}{
			"subscribed":                  false,
			"taskDailyDigestSubscribed":   false,
			"riskNotificationsSubscribed": true,
		}
		payloadJSON, err = json.Marshal(payload)
		suite.Require().NoError(err, "Failed to marshal unsubscribe request")

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("PUT", "/api/users/me/subscriptions", bytes.NewReader(payloadJSON))
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for unsubscribe digest")

		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Failed to unmarshal unsubscribe response")

		suite.False(response.Data.Subscribed, "Expected digest subscription to be updated to false")
		suite.False(response.Data.TaskDailyDigestSubscribed, "Expected task daily digest subscription to be updated to false")
		suite.True(response.Data.RiskNotificationsSubscribed, "Expected risk notifications subscription to be updated to true")
		suite.Equal([]string{"email", "slack"}, response.Data.Notifications[notification.NotificationTypeTaskAvailable], "Expected notifications to remain unchanged when omitted")
	})

	suite.Run("UpdateSubscriptionsInvalidPayload", func() {
		// Test with invalid type payload
		payload := map[string]string{"subscribed": "invalid"}
		payloadJSON, err := json.Marshal(payload)
		suite.Require().NoError(err, "Failed to marshal invalid subscriptions request")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/api/users/me/subscriptions", bytes.NewReader(payloadJSON))
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(400, rec.Code, "Expected Bad Request response for invalid payload")

		// Test with unsupported notification channel
		payload2 := map[string]interface{}{
			"notifications": map[string][]string{
				notification.NotificationTypeTaskAvailable: {"email", "pagerduty"},
			},
		}
		payloadJSON2, err := json.Marshal(payload2)
		suite.Require().NoError(err, "Failed to marshal invalid notification channels request")

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest("PUT", "/api/users/me/subscriptions", bytes.NewReader(payloadJSON2))
		req2.Header.Set("Authorization", "Bearer "+*token)
		req2.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec2, req2)
		suite.Equal(400, rec2.Code, "Expected Bad Request response for unsupported notification channel")

		// Test with unsupported notification type
		payload3 := map[string]interface{}{
			"notifications": map[string][]string{
				"task_due_soon": {"email"},
			},
		}
		payloadJSON3, err := json.Marshal(payload3)
		suite.Require().NoError(err, "Failed to marshal invalid notification type request")

		rec3 := httptest.NewRecorder()
		req3 := httptest.NewRequest("PUT", "/api/users/me/subscriptions", bytes.NewReader(payloadJSON3))
		req3.Header.Set("Authorization", "Bearer "+*token)
		req3.Header.Set("Content-Type", "application/json")

		suite.server.E().ServeHTTP(rec3, req3)
		suite.Equal(400, rec3.Code, "Expected Bad Request response for unsupported notification type")
	})

}
