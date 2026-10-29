//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

type SSPScopedEvidenceIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	scope  *sspscope.Service
	sspID  uuid.UUID
	token  string
}

func TestSSPScopedEvidence(t *testing.T) {
	suite.Run(t, new(SSPScopedEvidenceIntegrationSuite))
}

func (s *SSPScopedEvidenceIntegrationSuite) SetupTest() {
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
	s.token = s.roledToken("viewer@example.com", "viewer")
}

func (s *SSPScopedEvidenceIntegrationSuite) roledToken(email, role string) string {
	user := relational.User{Email: email, FirstName: "Scope", LastName: "Reader"}
	s.Require().NoError(s.DB.Create(&user).Error)
	if role != "" {
		s.Require().NoError(s.DB.Create(&relational.CCFRoleAssignment{
			RoleName:     role,
			AssigneeType: relational.RoleAssigneeTypeUser,
			AssigneeID:   relational.NormalizeAssigneeID(email),
		}).Error)
	}
	token, err := authn.GenerateJWTToken(&user, s.Config.JWTPrivateKey)
	s.Require().NoError(err)
	return *token
}

// createEvidence stores one evidence row of stream with the labels, ended age ago.
func (s *SSPScopedEvidenceIntegrationSuite) createEvidence(stream uuid.UUID, title string, age time.Duration, labels map[string]string) {
	rows := make([]relational.Labels, 0, len(labels))
	for name, value := range labels {
		rows = append(rows, relational.Labels{Name: name, Value: value})
	}
	end := time.Now().Add(-age)
	s.Require().NoError(s.DB.Create(&relational.Evidence{
		UUID:   stream,
		Title:  title,
		Start:  end.Add(-time.Minute),
		End:    end,
		Labels: rows,
	}).Error)
}

func (s *SSPScopedEvidenceIntegrationSuite) post(path, token string, filter labelfilter.Filter) *httptest.ResponseRecorder {
	body, err := json.Marshal(map[string]any{"filter": filter})
	s.Require().NoError(err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.server.E().ServeHTTP(rec, req)
	return rec
}

type scopedSearchResponse struct {
	Data  []PublicEvidenceResponse `json:"data"`
	Total int64                    `json:"total"`
}

func (s *SSPScopedEvidenceIntegrationSuite) search(filter labelfilter.Filter) scopedSearchResponse {
	rec := s.post("/api/oscal/system-security-plans/"+s.sspID.String()+"/evidence/search", s.token, filter)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var out scopedSearchResponse
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

func (s *SSPScopedEvidenceIntegrationSuite) seed() {
	streamA := uuid.New()
	s.createEvidence(streamA, "a-old", 2*time.Hour, map[string]string{"repo": "a", "env": "dev"})
	s.createEvidence(streamA, "a-latest", time.Hour, map[string]string{"repo": "a", "env": "prod"})
	s.createEvidence(uuid.New(), "b", time.Hour, map[string]string{"repo": "b"})
	s.createEvidence(uuid.New(), "acct-eu", time.Hour, map[string]string{"aws_account": "111", "region": "eu-west-1"})
	s.createEvidence(uuid.New(), "acct-us", time.Hour, map[string]string{"aws_account": "111", "region": "us-east-1"})
}

func (s *SSPScopedEvidenceIntegrationSuite) TestEmptyScopeReturnsNothing() {
	s.seed()
	out := s.search(labelfilter.Filter{})
	s.Zero(out.Total)
	s.Empty(out.Data)
}

func (s *SSPScopedEvidenceIntegrationSuite) TestSearchReturnsOnlyInScopeLatestEvidence() {
	s.seed()
	_, err := s.scope.AddEntry(s.sspID, []relational.ScopeLabel{{Key: "repo", Value: "A"}}, nil)
	s.Require().NoError(err)
	_, err = s.scope.AddEntry(s.sspID, []relational.ScopeLabel{{Key: "aws_account", Value: "111"}, {Key: "region", Value: "eu-west-1"}}, nil)
	s.Require().NoError(err)

	out := s.search(labelfilter.Filter{})
	s.EqualValues(2, out.Total)
	s.ElementsMatch([]string{"a-latest", "acct-eu"}, evidenceTitles(out.Data))

	// The request filter is ANDed with the scope.
	out = s.search(labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "env", Operator: "=", Value: "prod"}}})
	s.Equal([]string{"a-latest"}, evidenceTitles(out.Data))
	out = s.search(labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "repo", Operator: "=", Value: "b"}}})
	s.Zero(out.Total, "evidence outside the scope stays out whatever the request filter")
}

// The Evidence page sends {"filter":{"scope":{}}} when the search box is empty.
func (s *SSPScopedEvidenceIntegrationSuite) TestEmptyScopeObjectBodyReturnsInScopeEvidence() {
	s.seed()
	_, err := s.scope.AddEntry(s.sspID, []relational.ScopeLabel{{Key: "repo", Value: "a"}}, nil)
	s.Require().NoError(err)
	base := "/api/oscal/system-security-plans/" + s.sspID.String()
	emptyScope := labelfilter.Filter{Scope: &labelfilter.Scope{}}

	rec := s.post(base+"/evidence/search", s.token, emptyScope)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var out scopedSearchResponse
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out))
	s.Equal([]string{"a-latest"}, evidenceTitles(out.Data))

	rec = s.post(base+"/evidence/status-over-time?intervals=0m", s.token, emptyScope)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var overTime GenericDataListResponse[StatusInterval]
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &overTime))
	s.Require().Len(overTime.Data, 1)
	total := 0
	for _, status := range overTime.Data[0].Statuses {
		total += int(status.Count)
	}
	s.Equal(1, total)
}

func (s *SSPScopedEvidenceIntegrationSuite) TestStatusOverTimeRestrictedToScope() {
	s.seed()
	path := "/api/oscal/system-security-plans/" + s.sspID.String() + "/evidence/status-over-time?intervals=0m"

	count := func() int {
		rec := s.post(path, s.token, labelfilter.Filter{})
		s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
		var out GenericDataListResponse[StatusInterval]
		s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out))
		s.Require().Len(out.Data, 1)
		total := 0
		for _, status := range out.Data[0].Statuses {
			total += int(status.Count)
		}
		return total
	}
	s.Zero(count(), "empty scope")

	_, err := s.scope.AddEntry(s.sspID, []relational.ScopeLabel{{Key: "repo", Value: "b"}}, nil)
	s.Require().NoError(err)
	s.Equal(1, count())
}

func (s *SSPScopedEvidenceIntegrationSuite) TestAccess() {
	base := "/api/oscal/system-security-plans/"
	s.Equal(http.StatusUnauthorized, s.post(base+s.sspID.String()+"/evidence/search", "", labelfilter.Filter{}).Code)
	s.Equal(http.StatusForbidden, s.post(base+s.sspID.String()+"/evidence/search", s.roledToken("nobody@example.com", ""), labelfilter.Filter{}).Code)
	s.Equal(http.StatusNotFound, s.post(base+uuid.NewString()+"/evidence/search", s.token, labelfilter.Filter{}).Code)
	s.Equal(http.StatusBadRequest, s.post(base+"nope/evidence/search", s.token, labelfilter.Filter{}).Code)
}
