//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

const syncTestDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

type AgentConfigSyncIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	svc    *agentcfg.Service
}

func TestAgentConfigSyncAPI(t *testing.T) {
	suite.Run(t, new(AgentConfigSyncIntegrationSuite))
}

type syncAgent struct {
	agent *relational.Agent
	key   *relational.AgentServiceAccountKey
	token string
}

func (s *AgentConfigSyncIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
	// Public agent endpoints stay ENABLED: the sync routes must still require an agent JWT.
	s.Config.StrictDisablePublicAgentEndpoints = false
	s.server = s.buildServer()
	s.svc = agentcfg.NewService(s.DB, agentcfg.Settings{}, nil)
}

func (s *AgentConfigSyncIntegrationSuite) buildServer() *api.Server {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), s.Config, metrics)
	RegisterHandlers(server, logger.Sugar(), s.DB, s.Config, &APIServices{})
	return server
}

func (s *AgentConfigSyncIntegrationSuite) newAgent(name string) syncAgent {
	agent, err := s.CreateAgent(name)
	s.Require().NoError(err)
	key, _, err := s.CreateAgentKey(agent, name+"-key")
	s.Require().NoError(err)
	token, err := s.GetAgentToken(agent, key)
	s.Require().NoError(err)
	return syncAgent{agent: agent, key: key, token: *token}
}

func (s *AgentConfigSyncIntegrationSuite) do(server *api.Server, method, path, token string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	server.E().ServeHTTP(rec, req)
	return rec
}

func (s *AgentConfigSyncIntegrationSuite) getConfig(token, ifNoneMatch string) *httptest.ResponseRecorder {
	var headers map[string]string
	if ifNoneMatch != "" {
		headers = map[string]string{"If-None-Match": ifNoneMatch}
	}
	return s.do(s.server, http.MethodGet, "/api/agent/config", token, nil, headers)
}

func (s *AgentConfigSyncIntegrationSuite) createRevision(agentID uuid.UUID, expected int64, overlay string) *relational.AgentConfigRevision {
	rev, err := s.svc.CreateRevision(context.Background(), agentcfg.CreateRevisionParams{
		AgentID:          agentID,
		ExpectedRevision: expected,
		Overlay:          json.RawMessage(overlay),
		CreatedBy:        "test@example.com",
	})
	s.Require().NoError(err)
	return rev
}

func (s *AgentConfigSyncIntegrationSuite) instance(agentID, instanceID uuid.UUID) (relational.AgentInstance, bool) {
	var row relational.AgentInstance
	res := s.DB.Where("agent_id = ? AND instance_id = ?", agentID, instanceID).Limit(1).Find(&row)
	s.Require().NoError(res.Error)
	return row, res.RowsAffected == 1
}

func (s *AgentConfigSyncIntegrationSuite) assertRemoteConfigHeaders(rec *httptest.ResponseRecorder) {
	s.Equal("1", rec.Header().Get("X-CCF-Remote-Config"))
	s.Equal("no-cache", rec.Header().Get(echo.HeaderCacheControl))
}

// ---- GET /api/agent/config ----

func (s *AgentConfigSyncIntegrationSuite) TestGetConfigRevisionZero() {
	a := s.newAgent("rev-zero")
	wantTag := fmt.Sprintf(`"r0-%s"`, *a.agent.ID)

	rec := s.getConfig(a.token, "")
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.JSONEq(`{"data":{"revision":0,"overlay":{}}}`, rec.Body.String())
	s.Equal(wantTag, rec.Header().Get("ETag"))
	s.assertRemoteConfigHeaders(rec)

	rec = s.getConfig(a.token, wantTag)
	s.Require().Equal(http.StatusNotModified, rec.Code)
	s.Empty(rec.Body.Bytes())
	s.Equal(wantTag, rec.Header().Get("ETag"))
	s.assertRemoteConfigHeaders(rec)

	// A tag for some other agent's revision 0 does not match.
	rec = s.getConfig(a.token, fmt.Sprintf(`"r0-%s"`, uuid.New()))
	s.Equal(http.StatusOK, rec.Code)
}

func (s *AgentConfigSyncIntegrationSuite) TestGetConfigAfterRevision() {
	a := s.newAgent("with-revision")
	r0Tag := fmt.Sprintf(`"r0-%s"`, *a.agent.ID)
	overlay := `{"plugins":{"x":{"schedule":"*/5 * * * *"}}}`
	rev := s.createRevision(*a.agent.ID, 0, overlay)
	r1Tag := fmt.Sprintf(`"r1-%s"`, *rev.ID)

	rec := s.getConfig(a.token, "")
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(r1Tag, rec.Header().Get("ETag"))
	s.assertRemoteConfigHeaders(rec)
	var got struct {
		Data struct {
			Revision  int64           `json:"revision"`
			Overlay   json.RawMessage `json:"overlay"`
			CreatedAt *time.Time      `json:"created-at"`
		} `json:"data"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &got))
	s.Equal(int64(1), got.Data.Revision)
	s.JSONEq(overlay, string(got.Data.Overlay))
	s.Require().NotNil(got.Data.CreatedAt)
	s.WithinDuration(rev.CreatedAt, *got.Data.CreatedAt, time.Second)

	// The previous revision-0 tag no longer matches.
	rec = s.getConfig(a.token, r0Tag)
	s.Equal(http.StatusOK, rec.Code)

	bare := strings.Trim(r1Tag, `"`)
	for _, inm := range []string{
		r1Tag,
		"W/" + r1Tag,
		bare,
		fmt.Sprintf(`%s, "r7-%s", %s`, r0Tag, uuid.New(), r1Tag),
		"*",
	} {
		rec = s.getConfig(a.token, inm)
		s.Equal(http.StatusNotModified, rec.Code, "If-None-Match %q", inm)
		s.Empty(rec.Body.Bytes(), "If-None-Match %q", inm)
		s.Equal(r1Tag, rec.Header().Get("ETag"))
		s.assertRemoteConfigHeaders(rec)
	}
}

func (s *AgentConfigSyncIntegrationSuite) TestGetConfigAfterSimulatedReset() {
	a := s.newAgent("reset")
	old := s.createRevision(*a.agent.ID, 0, `{"a":1}`)
	oldTag := fmt.Sprintf(`"r1-%s"`, *old.ID)
	s.Require().Equal(http.StatusNotModified, s.getConfig(a.token, oldTag).Code)

	// The gorm model is append-only (BeforeDelete hook), so reset with raw SQL.
	s.Require().NoError(s.DB.Exec("DELETE FROM ccf_agent_config_revisions").Error)
	recreated := s.createRevision(*a.agent.ID, 0, `{"a":1}`)
	s.Require().NotEqual(*old.ID, *recreated.ID)

	rec := s.getConfig(a.token, oldTag)
	s.Require().Equal(http.StatusOK, rec.Code, "same revision number, different row: no false 304")
	s.Equal(fmt.Sprintf(`"r1-%s"`, *recreated.ID), rec.Header().Get("ETag"))
}

func (s *AgentConfigSyncIntegrationSuite) TestGetConfigAuth() {
	a := s.newAgent("auth")

	s.Equal(http.StatusUnauthorized, s.getConfig("", "").Code, "no token, public agent endpoints on")

	userToken, err := s.GetAuthToken()
	s.Require().NoError(err)
	s.Equal(http.StatusUnauthorized, s.getConfig(*userToken, "").Code, "user JWT")

	s.Equal(http.StatusUnauthorized, s.getConfig("not-a-jwt", "").Code, "garbage token")

	s.Require().Equal(http.StatusOK, s.getConfig(a.token, "").Code)

	// Revoked key.
	revoked := time.Now().UTC().Add(-time.Minute)
	s.Require().NoError(s.DB.Model(&relational.AgentServiceAccountKey{}).Where("id = ?", *a.key.ID).Update("revoked_at", revoked).Error)
	s.Equal(http.StatusForbidden, s.getConfig(a.token, "").Code, "revoked key")

	// Inactive agent.
	b := s.newAgent("inactive")
	s.Require().NoError(s.DB.Exec("UPDATE ccf_agents SET is_active = false WHERE id = ?", *b.agent.ID).Error)
	s.Equal(http.StatusForbidden, s.getConfig(b.token, "").Code, "inactive agent")
}

func (s *AgentConfigSyncIntegrationSuite) TestGetConfigCrossAgentIsolation() {
	a := s.newAgent("agent-a")
	b := s.newAgent("agent-b")
	c := s.newAgent("agent-c")
	s.createRevision(*a.agent.ID, 0, `{"who":"a"}`)
	s.createRevision(*a.agent.ID, 1, `{"who":"a2"}`)
	revB := s.createRevision(*b.agent.ID, 0, `{"who":"b"}`)

	rec := s.getConfig(b.token, "")
	s.Require().Equal(http.StatusOK, rec.Code)
	var got GenericDataResponse[agentconfig.OverlayDocument]
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &got))
	s.Equal(int64(1), got.Data.Revision)
	s.JSONEq(`{"who":"b"}`, string(got.Data.Overlay))
	s.Equal(fmt.Sprintf(`"r1-%s"`, *revB.ID), rec.Header().Get("ETag"))

	rec = s.getConfig(a.token, "")
	s.Require().Equal(http.StatusOK, rec.Code)
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &got))
	s.Equal(int64(2), got.Data.Revision)
	s.JSONEq(`{"who":"a2"}`, string(got.Data.Overlay))

	rec = s.getConfig(c.token, "")
	s.Require().Equal(http.StatusOK, rec.Code)
	s.JSONEq(`{"data":{"revision":0,"overlay":{}}}`, rec.Body.String())
	s.Equal(fmt.Sprintf(`"r0-%s"`, *c.agent.ID), rec.Header().Get("ETag"))
}

// ---- PUT /api/agent/instances/:instanceId/config-report ----

// ---- POST /api/agent/heartbeat ----

func (s *AgentConfigSyncIntegrationSuite) heartbeat(token string, instanceID uuid.UUID, rev *int64, digest *string) *httptest.ResponseRecorder {
	raw, err := json.Marshal(HeartbeatCreateRequest{
		UUID:           instanceID,
		CreatedAt:      time.Now().UTC(),
		ConfigRevision: rev,
		ConfigDigest:   digest,
	})
	s.Require().NoError(err)
	return s.do(s.server, http.MethodPost, "/api/agent/heartbeat", token, raw, nil)
}

func (s *AgentConfigSyncIntegrationSuite) TestHeartbeatWithDigestRegistersInstance() {
	a := s.newAgent("hb-digest")
	instanceID := uuid.New()
	rev := int64(3)
	digest := syncTestDigest

	rec := s.heartbeat(a.token, instanceID, &rev, &digest)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	row, ok := s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	s.Require().NotNil(row.HeartbeatConfigDigest)
	s.Equal(syncTestDigest, *row.HeartbeatConfigDigest)
	s.Require().NotNil(row.HeartbeatConfigRevision)
	s.Equal(int64(3), *row.HeartbeatConfigRevision)
	s.Empty(row.ReportedStatus)
	s.Empty(row.Mode)
	s.Nil(row.ReportedAt)
	s.Require().NotNil(row.CredentialID)
	s.Equal(*a.key.ID, *row.CredentialID)
}

func (s *AgentConfigSyncIntegrationSuite) TestHeartbeatMalformedDigestAndAnonymous() {
	a := s.newAgent("hb-malformed")
	instanceID := uuid.New()
	rev := int64(1)
	bad := "sha256:not-hex"

	rec := s.heartbeat(a.token, instanceID, &rev, &bad)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	_, ok := s.instance(*a.agent.ID, instanceID)
	s.False(ok, "a malformed digest is treated as absent")

	digest := syncTestDigest
	rec = s.heartbeat("", uuid.New(), &rev, &digest)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var count int64
	s.Require().NoError(s.DB.Model(&relational.AgentInstance{}).Count(&count).Error)
	s.Equal(int64(0), count, "anonymous heartbeats never touch the instance registry")
}
