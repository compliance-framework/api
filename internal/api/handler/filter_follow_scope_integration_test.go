//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/service/relational/sspscope"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type FilterFollowScopeIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	scope  *sspscope.Service
	sspID  uuid.UUID
	token  string
}

func TestFilterFollowScope(t *testing.T) {
	suite.Run(t, new(FilterFollowScopeIntegrationSuite))
}

func (s *FilterFollowScopeIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
	logger := zap.NewNop().Sugar()
	pdp, err := authz.Open(authz.Options{Driver: authz.DriverCedar}, authz.Deps{DB: s.DB, Config: s.Config, Logger: logger})
	s.Require().NoError(err)
	s.server = api.NewServer(context.Background(), logger, s.Config, api.NewMetricsHandler(context.Background(), logger))
	RegisterHandlers(s.server, logger, s.DB, s.Config, &APIServices{
		EvidenceService: evidencesvc.NewEvidenceService(s.DB, logger, s.Config, nil),
		PEP:             middleware.NewPEP(pdp, authz.FailClosed, logger),
	})
	s.scope = sspscope.NewService(s.DB)
	s.sspID = uuid.New()
	s.Require().NoError(s.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &s.sspID}}).Error)

	user := relational.User{Email: "contributor@example.com", FirstName: "Filter", LastName: "Author"}
	s.Require().NoError(s.DB.Create(&user).Error)
	s.Require().NoError(s.DB.Create(&relational.CCFRoleAssignment{
		RoleName:     "contributor",
		AssigneeType: relational.RoleAssigneeTypeUser,
		AssigneeID:   relational.NormalizeAssigneeID(user.Email),
	}).Error)
	token, err := authn.GenerateJWTToken(&user, s.Config.JWTPrivateKey)
	s.Require().NoError(err)
	s.token = *token
}

func (s *FilterFollowScopeIntegrationSuite) send(method, path string, body any) (int, relational.Filter) {
	raw, err := json.Marshal(body)
	s.Require().NoError(err)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+s.token)
	rec := httptest.NewRecorder()
	s.server.E().ServeHTTP(rec, req)
	var out GenericDataResponse[relational.Filter]
	if rec.Code < 300 {
		s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	}
	return rec.Code, out.Data
}

func envFilter(value string) labelfilter.Filter {
	return labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "env", Operator: "=", Value: value}}}
}

// matches reports which label sets the filter's stored expression matches:
// 0 = prod/repo a, 1 = prod/repo b, 2 = dev/repo a.
func (s *FilterFollowScopeIntegrationSuite) matches(filter labelfilter.Filter) []int {
	got, err := labelfilter.NewIndex([]map[string][]string{
		{"env": {"prod"}, "repo": {"a"}},
		{"env": {"prod"}, "repo": {"b"}},
		{"env": {"dev"}, "repo": {"a"}},
	}).Match(filter.Scope)
	s.Require().NoError(err)
	return got
}

func (s *FilterFollowScopeIntegrationSuite) storedFilter(id uuid.UUID) relational.Filter {
	var filter relational.Filter
	s.Require().NoError(s.DB.First(&filter, "id = ?", id).Error)
	return filter
}

func (s *FilterFollowScopeIntegrationSuite) TestCreateRequiresSSPAndScope() {
	follow := true
	code, _ := s.send(http.MethodPost, "/api/filters", map[string]any{"name": "f", "filter": envFilter("prod"), "followSspScope": follow})
	s.Equal(http.StatusBadRequest, code, "needs sspId")

	code, _ = s.send(http.MethodPost, "/api/filters", map[string]any{"name": "f", "sspId": s.sspID, "filter": envFilter("prod"), "followSspScope": follow})
	s.Equal(http.StatusBadRequest, code, "needs a non-empty scope")

	code, created := s.send(http.MethodPost, "/api/filters", map[string]any{"name": "plain", "sspId": s.sspID, "filter": envFilter("prod")})
	s.Require().Equal(http.StatusCreated, code)
	s.Nil(created.ScopeBase)
	s.Equal(relational.FilterOriginManual, created.Origin)
}

func (s *FilterFollowScopeIntegrationSuite) TestFollowingFilterLifecycle() {
	_, err := s.scope.AddEntry(s.sspID, []relational.ScopeLabel{{Key: "repo", Value: "a"}}, nil)
	s.Require().NoError(err)

	code, created := s.send(http.MethodPost, "/api/filters", map[string]any{
		"name": "prod", "sspId": s.sspID, "filter": envFilter("prod"), "followSspScope": true,
	})
	s.Require().Equal(http.StatusCreated, code)
	s.Require().NotNil(created.ScopeBase)
	s.Equal(envFilter("prod"), created.ScopeBase.Data())
	s.Equal(relational.FilterOriginManual, created.Origin)
	s.Equal([]int{0}, s.matches(created.Filter.Data()), "filter is the base AND the scope")

	// A scope change rewrites the stored expression.
	_, err = s.scope.AddEntry(s.sspID, []relational.ScopeLabel{{Key: "repo", Value: "b"}}, nil)
	s.Require().NoError(err)
	s.Equal([]int{0, 1}, s.matches(s.storedFilter(*created.ID).Filter.Data()))

	// Omitting followSspScope keeps following; the request filter is the new base.
	path := "/api/filters/" + created.ID.String()
	code, updated := s.send(http.MethodPut, path, map[string]any{"name": "dev", "sspId": s.sspID, "filter": envFilter("dev")})
	s.Require().Equal(http.StatusOK, code)
	s.Require().NotNil(updated.ScopeBase)
	s.Equal(envFilter("dev"), updated.ScopeBase.Data())
	s.Equal([]int{2}, s.matches(updated.Filter.Data()))

	// followSspScope: false stops following and keeps the current effective filter,
	// whatever filter the request carries.
	code, updated = s.send(http.MethodPut, path, map[string]any{"name": "dev", "sspId": s.sspID, "filter": envFilter("prod"), "followSspScope": false})
	s.Require().Equal(http.StatusOK, code)
	s.Nil(updated.ScopeBase)
	s.Equal([]int{2}, s.matches(updated.Filter.Data()))
	stored := s.storedFilter(*created.ID)
	s.Nil(stored.ScopeBase)

	// It no longer follows: scope changes leave it alone.
	_, err = s.scope.AddEntry(s.sspID, []relational.ScopeLabel{{Key: "repo", Value: "c"}}, nil)
	s.Require().NoError(err)
	s.Equal(stored.Filter, s.storedFilter(*created.ID).Filter)

	// Following again, then losing the SSP, is refused.
	code, _ = s.send(http.MethodPut, path, map[string]any{"name": "dev", "filter": envFilter("prod"), "followSspScope": true})
	s.Equal(http.StatusBadRequest, code)
}
