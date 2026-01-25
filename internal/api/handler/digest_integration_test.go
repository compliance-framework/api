//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/scheduler"
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
	mockScheduler *MockScheduler
	emailService  *email.Service
}

// MockScheduler implements the scheduler.Service interface for testing
type MockScheduler struct {
	jobs map[string]bool
}

func NewMockScheduler() *MockScheduler {
	return &MockScheduler{
		jobs: make(map[string]bool),
	}
}

func (m *MockScheduler) Start() {
	// Mock implementation
}

func (m *MockScheduler) Stop() context.Context {
	// Mock implementation
	return context.Background()
}

func (m *MockScheduler) Schedule(schedule scheduler.Schedule, job scheduler.Job) error {
	m.jobs[job.Name()] = true
	return nil
}

func (m *MockScheduler) ScheduleCron(cronExpr string, job scheduler.Job) error {
	m.jobs[job.Name()] = true
	return nil
}

func (m *MockScheduler) RunNow(ctx context.Context, name string) error {
	if _, exists := m.jobs[name]; !exists {
		return fmt.Errorf("job %q not found", name)
	}
	// Mock job execution
	return nil
}

func (m *MockScheduler) ListJobs() []string {
	var jobs []string
	for name := range m.jobs {
		jobs = append(jobs, name)
	}
	return jobs
}

func (suite *DigestApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()

	// Create email service
	emailService, err := email.NewService(suite.Config.Email, suite.logger)
	suite.Require().NoError(err, "Failed to create email service")
	suite.emailService = emailService

	// Create mock scheduler
	suite.mockScheduler = NewMockScheduler()

	// Create digest handler
	digestService := digest.NewService(suite.DB, suite.emailService, nil, suite.Config, suite.logger)
	suite.digestHandler = NewDigestHandler(digestService, suite.mockScheduler, suite.logger)

	// Setup server
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)

	// Register handlers
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config, digestService, suite.mockScheduler)
}

func (suite *DigestApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	// Pre-register the default job in the mock scheduler
	suite.mockScheduler.jobs["global-evidence-digest"] = true
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
		// Pre-register the custom job
		suite.mockScheduler.jobs["custom-job"] = true

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/digest/trigger?job=custom-job", nil)
		req.Header.Set("Authorization", "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(200, rec.Code, "Expected OK response for TriggerDigest with custom job")

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err, "Failed to unmarshal TriggerDigest response")

		suite.Equal("Digest job triggered successfully", response["message"])
		suite.Equal("custom-job", response["job"])
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

func (suite *DigestApiIntegrationSuite) TestTriggerDigestWithNilScheduler() {
	// Test with nil scheduler to verify error handling
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	// Create handler with nil scheduler
	digestService := digest.NewService(suite.DB, suite.emailService, nil, suite.Config, suite.logger)
	nilSchedulerHandler := NewDigestHandler(digestService, nil, suite.logger)

	// Create a temporary echo context for testing
	e := suite.server.E()
	req := httptest.NewRequest("POST", "/api/admin/digest/trigger", nil)
	req.Header.Set("Authorization", "Bearer "+*token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = nilSchedulerHandler.TriggerDigest(c)
	suite.NoError(err, "Expected no error from TriggerDigest with nil scheduler")
	suite.Equal(500, rec.Code, "Expected Internal Server Error when scheduler is nil")

	var response api.Error
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal error response")

	// Check if the error contains our expected message
	for _, errMsg := range response.Errors {
		if msgStr, ok := errMsg.(string); ok {
			suite.Contains(msgStr, "scheduler is not available")
		}
	}
}
