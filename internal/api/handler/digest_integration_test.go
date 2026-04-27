//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/email"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestDigestApi(t *testing.T) {
	suite.Run(t, new(DigestApiIntegrationSuite))
}

type DigestApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server        *api.Server
	logger        *zap.SugaredLogger
	digestHandler *DigestHandler
	emailService  *email.Service
}

func (suite *DigestApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()

	// Create email service
	emailService, err := email.NewService(suite.Config.Email, suite.logger)
	suite.Require().NoError(err, "Failed to create email service")
	suite.emailService = emailService

	slackService, err := slacksvc.NewService(suite.Config.Slack, suite.logger)
	suite.Require().NoError(err, "Failed to create slack service")
	runtimeProvider := digest.NewRuntimeProvider(
		suite.emailService,
		nil,
		slackService,
	)

	// Create digest handler
	notifier := digest.NewNotificationService(
		suite.DB,
		suite.Config,
		runtimeProvider,
	)
	digestService := digest.NewService(suite.DB, notifier, suite.Config, suite.logger)
	suite.digestHandler = NewDigestHandler(digestService, suite.logger)

	// Setup server
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)

	// Register handlers
	services := &APIServices{}
	services.DigestService = digestService
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config, services)
}

func (suite *DigestApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

}

func (suite *DigestApiIntegrationSuite) TestTriggerDigest() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	suite.Run("TriggerDigestSuccess", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/digest/trigger", nil)
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for TriggerDigest")

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Failed to unmarshal TriggerDigest response")

		suite.Equal("Digest job triggered successfully", response["message"])
		suite.Equal("global-evidence-digest", response["job"])
	})

	suite.Run("TriggerDigestWithCustomJob", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/digest/trigger?job=custom-job", nil)
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(400, rec.Code, "Expected Bad Request response for unsupported custom digest job")

		var response api.Error
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Failed to unmarshal TriggerDigest error response")
	})

	suite.Run("TriggerDigestUnauthorized", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/digest/trigger", nil)
		// No authorization header

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(401, rec.Code, "Expected Unauthorized response for missing token")
	})
}

func (suite *DigestApiIntegrationSuite) TestPreviewDigest() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	suite.Run("PreviewDigestSuccess", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/admin/digest/preview", nil)
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for PreviewDigest")

		var response struct {
			Data *digest.EvidenceSummary `json:"data"`
		}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Failed to unmarshal PreviewDigest response")

		suite.NotNil(response.Data, "Expected evidence summary data")
	})

	suite.Run("PreviewDigestUnauthorized", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/admin/digest/preview", nil)
		// No authorization header

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(401, rec.Code, "Expected Unauthorized response for missing token")
	})
}
