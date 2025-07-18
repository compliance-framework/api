// go build:integration
package handler

import (
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
