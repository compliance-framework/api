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
	"github.com/compliance-framework/api/internal/config"
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

func (s *AgentConfigSyncIntegrationSuite) putReport(server *api.Server, token string, instanceID string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var raw []byte
	switch b := body.(type) {
	case []byte:
		raw = b
	default:
		var err error
		raw, err = json.Marshal(body)
		s.Require().NoError(err)
	}
	return s.do(server, http.MethodPut, "/api/agent/instances/"+instanceID+"/config-report", token, raw, headers)
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

func validReportBody() map[string]any {
	return map[string]any{
		"hostname":         "host-1",
		"agent-version":    "v0.9.0",
		"mode":             agentconfig.ModeApplySafe,
		"daemon":           true,
		"applied-revision": 0,
		"status":           agentconfig.StatusApplied,
		"error":            nil,
		"base":             map[string]any{"api": map[string]any{"url": "http://api"}},
		"effective":        map[string]any{"api": map[string]any{"url": "http://api"}},
		"effective-digest": syncTestDigest,
	}
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
	s.Equal(http.StatusForbidden, s.putReport(s.server, b.token, uuid.NewString(), validReportBody(), nil).Code, "inactive agent report")
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

func (s *AgentConfigSyncIntegrationSuite) TestPutReportStored() {
	a := s.newAgent("reporter")
	instanceID := uuid.New()
	body := validReportBody()
	body["daemon"] = false
	body["truncated"] = true
	body["mode"] = agentconfig.ModeReport
	body["status"] = agentconfig.StatusNotApplicable
	body["attempted-revision"] = 0
	body["warnings"] = []map[string]any{{"path": "/plugins/x/schedule", "code": "cron", "message": "bad cron"}}

	rec := s.putReport(s.server, a.token, instanceID.String(), body, nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	s.assertRemoteConfigHeaders(rec)

	row, ok := s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	s.Equal(agentconfig.ModeReport, row.Mode)
	s.Require().NotNil(row.Daemon)
	s.False(*row.Daemon)
	s.True(row.Truncated)
	s.Equal(agentconfig.StatusNotApplicable, row.ReportedStatus)
	s.Require().NotNil(row.CredentialID)
	s.Equal(*a.key.ID, *row.CredentialID)
	s.Require().NotNil(row.EffectiveDigest)
	s.Equal(syncTestDigest, *row.EffectiveDigest)
	s.Require().NotNil(row.Hostname)
	s.Equal("host-1", *row.Hostname)
	s.Require().NotNil(row.AppliedRevision)
	s.Equal(int64(0), *row.AppliedRevision)
	s.NotNil(row.ReportedAt)
	s.Nil(row.ApplyError)
	s.JSONEq(`{"api":{"url":"http://api"}}`, string(row.BaseConfig))
	s.JSONEq(`[{"path":"/plugins/x/schedule","code":"cron","message":"bad cron"}]`, string(row.Warnings))

	// A second report updates the same row.
	body = validReportBody()
	body["status"] = agentconfig.StatusRejected
	body["reason"] = agentconfig.ReasonUnsafeChanges
	body["error"] = "nope"
	rec = s.putReport(s.server, a.token, instanceID.String(), body, nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	row, _ = s.instance(*a.agent.ID, instanceID)
	s.Equal(agentconfig.StatusRejected, row.ReportedStatus)
	s.Equal(agentconfig.ModeApplySafe, row.Mode)
	s.Require().NotNil(row.ApplyReason)
	s.Equal(agentconfig.ReasonUnsafeChanges, *row.ApplyReason)
	s.Require().NotNil(row.ApplyError)
	s.Equal("nope", *row.ApplyError)
	var count int64
	s.Require().NoError(s.DB.Model(&relational.AgentInstance{}).Where("agent_id = ?", *a.agent.ID).Count(&count).Error)
	s.Equal(int64(1), count)
}

// TestPutReportArtifactDigests: artifact-digest on a bundle and its extends tree is stored
// as sent, even when files were dropped to fit the report, and need not name a stored
// artifact (R62).
func (s *AgentConfigSyncIntegrationSuite) TestPutReportArtifactDigests() {
	a := s.newAgent("artifact-digests")
	instanceID := uuid.New()
	inlineArtifact := "sha256:" + strings.Repeat("1", 64)
	vendorArtifact := "sha256:" + strings.Repeat("2", 64)
	body := validReportBody()
	body["truncated"] = true
	body["policy-bundles"] = []map[string]any{{
		"source":          "inline:custom",
		"digest":          "tree:" + syncTestDigest,
		"files":           []any{},
		"artifact-digest": inlineArtifact,
		"extends": map[string]any{
			"source":          "ghcr.io/vendor/ssh-policies:v1",
			"digest":          "tree:" + syncTestDigest,
			"files":           []any{},
			"artifact-digest": vendorArtifact,
		},
	}, {
		"source": "ghcr.io/vendor/other:v1",
		"digest": "tree:" + syncTestDigest,
		"files":  []any{},
	}}

	rec := s.putReport(s.server, a.token, instanceID.String(), body, nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	row, ok := s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	var stored []agentconfig.PolicyBundleReport
	s.Require().NoError(json.Unmarshal(row.PolicyBundles, &stored))
	s.Require().Len(stored, 2)
	s.Equal(inlineArtifact, stored[0].ArtifactDigest)
	s.Require().NotNil(stored[0].Extends)
	s.Equal(vendorArtifact, stored[0].Extends.ArtifactDigest)
	s.Empty(stored[1].ArtifactDigest)
	s.NotContains(string(row.PolicyBundles), `"artifact-digest":""`, "omitted when empty")
}

// TestPutReportPlugins: plugins[] (R76) is stored as sent and replaced by the next report; an
// agent that omits it clears it.
func (s *AgentConfigSyncIntegrationSuite) TestPutReportPlugins() {
	a := s.newAgent("plugins")
	instanceID := uuid.New()
	body := validReportBody()
	body["plugins"] = []map[string]any{
		{"name": "ssh", "source": "ghcr.io/compliance-framework/plugin-local-ssh:v0.2.0", "lib-version": "v0.1.9"},
		{"name": "local", "source": "/plugins/local"},
	}

	rec := s.putReport(s.server, a.token, instanceID.String(), body, nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	row, ok := s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	var plugins []agentconfig.PluginReport
	s.Require().NoError(json.Unmarshal(row.Plugins, &plugins))
	s.Equal([]agentconfig.PluginReport{
		{Name: "ssh", Source: "ghcr.io/compliance-framework/plugin-local-ssh:v0.2.0", LibVersion: "v0.1.9"},
		{Name: "local", Source: "/plugins/local"},
	}, plugins)
	s.NotContains(string(row.Plugins), `"lib-version":""`, "omitted when unknown")

	// An older agent's report has none: it is cleared.
	rec = s.putReport(s.server, a.token, instanceID.String(), validReportBody(), nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	row, ok = s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	s.Empty(row.Plugins)
}

func (s *AgentConfigSyncIntegrationSuite) TestPutReportReRedacts() {
	a := s.newAgent("redact")
	instanceID := uuid.New()
	leaky := map[string]any{
		"api": map[string]any{
			"url":  "http://api",
			"auth": map[string]any{"client_id": "cid", "client_secret": "super-secret"},
		},
		"plugins": map[string]any{
			"x": map[string]any{
				"source": "ghcr.io/compliance-framework/x:v1",
				"config": map[string]any{
					"password": "hunter2",
					"api_key":  "${env:X_API_KEY}",
					"region":   "eu-west-1",
				},
			},
		},
	}
	body := validReportBody()
	body["base"] = leaky
	body["effective"] = leaky

	rec := s.putReport(s.server, a.token, instanceID.String(), body, nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	row, ok := s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	for name, raw := range map[string][]byte{"base": row.BaseConfig, "effective": row.EffectiveConfig} {
		var doc map[string]any
		s.Require().NoError(json.Unmarshal(raw, &doc), name)
		auth := doc["api"].(map[string]any)["auth"].(map[string]any)
		s.NotContains(auth, "client_secret", name)
		s.Equal("cid", auth["client_id"], name)
		cfg := doc["plugins"].(map[string]any)["x"].(map[string]any)["config"].(map[string]any)
		s.Equal(agentconfig.MaskedValue, cfg["password"], name)
		s.Equal("${env:X_API_KEY}", cfg["api_key"], name)
		s.Equal("eu-west-1", cfg["region"], name)
		s.NotContains(string(raw), "super-secret", name)
		s.NotContains(string(raw), "hunter2", name)
	}
	s.Require().NotNil(row.EffectiveDigest)
	s.Equal(syncTestDigest, *row.EffectiveDigest, "digest stored exactly as sent, never recomputed")
}

func (s *AgentConfigSyncIntegrationSuite) TestPutReportValidation() {
	a := s.newAgent("validation")
	instanceID := uuid.NewString()

	cases := map[string]func(b map[string]any){
		"status pending":            func(b map[string]any) { b["status"] = agentconfig.StatusPending },
		"status unknown":            func(b map[string]any) { b["status"] = agentconfig.StatusUnknown },
		"unknown reason":            func(b map[string]any) { b["reason"] = "cosmic-rays" },
		"bad mode":                  func(b map[string]any) { b["mode"] = "apply" },
		"missing mode":              func(b map[string]any) { delete(b, "mode") },
		"bad digest":                func(b map[string]any) { b["effective-digest"] = "sha256:XYZ" },
		"uppercase digest":          func(b map[string]any) { b["effective-digest"] = strings.ToUpper(syncTestDigest) },
		"base not an object":        func(b map[string]any) { b["base"] = []any{1, 2} },
		"base null":                 func(b map[string]any) { b["base"] = nil },
		"effective not an object":   func(b map[string]any) { b["effective"] = "x" },
		"negative applied-revision": func(b map[string]any) { b["applied-revision"] = -1 },
		"negative attempted":        func(b map[string]any) { b["attempted-revision"] = -3 },
		"wrong type":                func(b map[string]any) { b["daemon"] = "yes" },
		"bad artifact-digest": func(b map[string]any) {
			b["policy-bundles"] = []map[string]any{{"source": "inline:a", "digest": "tree:" + syncTestDigest, "files": []any{}, "artifact-digest": "sha256:XYZ"}}
		},
		"plugin without a name": func(b map[string]any) {
			b["plugins"] = []map[string]any{{"source": "ghcr.io/x/p:1", "lib-version": "v0.7.1"}}
		},
		"plugins not a list": func(b map[string]any) { b["plugins"] = map[string]any{"ssh": "v0.7.1"} },
		"bad extends artifact-digest": func(b map[string]any) {
			b["policy-bundles"] = []map[string]any{{"source": "inline:a", "digest": "tree:" + syncTestDigest, "files": []any{},
				"extends": map[string]any{"source": "ghcr.io/v/p:1", "digest": "tree:" + syncTestDigest, "files": []any{}, "artifact-digest": "nope"}}}
		},
	}
	for name, mutate := range cases {
		body := validReportBody()
		mutate(body)
		rec := s.putReport(s.server, a.token, instanceID, body, nil)
		s.Equal(http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}

	rec := s.putReport(s.server, a.token, instanceID, []byte(`{not json`), nil)
	s.Equal(http.StatusBadRequest, rec.Code, "malformed JSON")

	rec = s.putReport(s.server, a.token, "not-a-uuid", validReportBody(), nil)
	s.Equal(http.StatusBadRequest, rec.Code, "invalid instance id")

	_, ok := s.instance(*a.agent.ID, uuid.MustParse(instanceID))
	s.False(ok, "no rejected report is stored")
}

func (s *AgentConfigSyncIntegrationSuite) TestPutReportContentTypeAndSize() {
	a := s.newAgent("content-type")
	raw, err := json.Marshal(validReportBody())
	s.Require().NoError(err)

	rec := s.putReport(s.server, a.token, uuid.NewString(), raw, map[string]string{echo.HeaderContentType: "text/plain"})
	s.Equal(http.StatusUnsupportedMediaType, rec.Code, rec.Body.String())

	rec = s.putReport(s.server, a.token, uuid.NewString(), raw, map[string]string{echo.HeaderContentType: "application/json; charset=utf-8"})
	s.Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	// Over 4 MiB: 413 (padding inside a valid JSON document).
	body := validReportBody()
	body["hostname"] = strings.Repeat("h", agentconfig.MaxReportBytes)
	rec = s.putReport(s.server, a.token, uuid.NewString(), body, nil)
	s.Equal(http.StatusRequestEntityTooLarge, rec.Code)

	// No token.
	rec = s.putReport(s.server, "", uuid.NewString(), raw, nil)
	s.Equal(http.StatusUnauthorized, rec.Code)

	userToken, err := s.GetAuthToken()
	s.Require().NoError(err)
	rec = s.putReport(s.server, *userToken, uuid.NewString(), raw, nil)
	s.Equal(http.StatusUnauthorized, rec.Code, "user JWT")
}

func (s *AgentConfigSyncIntegrationSuite) TestPutReportTruncation() {
	a := s.newAgent("truncation")
	instanceID := uuid.New()
	body := validReportBody()
	body["status"] = agentconfig.StatusFailed
	body["reason"] = agentconfig.ReasonInternal
	body["error"] = strings.Repeat("e", 9000)
	warnings := make([]map[string]any, 501)
	for i := range warnings {
		warnings[i] = map[string]any{"path": fmt.Sprintf("/plugins/p%d", i), "code": "cron", "message": "bad"}
	}
	body["warnings"] = warnings
	body["truncated"] = false

	rec := s.putReport(s.server, a.token, instanceID.String(), body, nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	row, ok := s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	s.Require().NotNil(row.ApplyError)
	s.LessOrEqual(len(*row.ApplyError), 8192)
	s.NotEmpty(*row.ApplyError)
	var stored []agentconfig.FieldError
	s.Require().NoError(json.Unmarshal(row.Warnings, &stored))
	s.Len(stored, 500)
	s.Equal("/plugins/p499", stored[499].Path)
	s.True(row.Truncated)
}

func (s *AgentConfigSyncIntegrationSuite) TestPutReportInstanceCap() {
	saved := s.Config.Agents
	defer func() { s.Config.Agents = saved }()
	cfg := config.DefaultAgentsConfig()
	cfg.MaxInstancesPerAgent = 1
	s.Config.Agents = cfg
	server := s.buildServer()

	a := s.newAgent("capped")
	first := uuid.NewString()
	rec := s.putReport(server, a.token, first, validReportBody(), nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	rec = s.putReport(server, a.token, uuid.NewString(), validReportBody(), nil)
	s.Require().Equal(http.StatusConflict, rec.Code, rec.Body.String())
	s.JSONEq(`{"errors":{"body":"instance limit reached"}}`, rec.Body.String())

	// The existing instance can still report.
	rec = s.putReport(server, a.token, first, validReportBody(), nil)
	s.Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	// The cap is per agent.
	b := s.newAgent("capped-b")
	rec = s.putReport(server, b.token, uuid.NewString(), validReportBody(), nil)
	s.Equal(http.StatusNoContent, rec.Code, rec.Body.String())
}

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

func (s *AgentConfigSyncIntegrationSuite) TestHeartbeatWithoutDigest() {
	a := s.newAgent("hb-no-digest")
	instanceID := uuid.New()

	rec := s.heartbeat(a.token, instanceID, nil, nil)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	_, ok := s.instance(*a.agent.ID, instanceID)
	s.False(ok, "a heartbeat without a digest never inserts")

	// Once a report exists, a digest-less heartbeat only refreshes last_seen_at.
	rec = s.putReport(s.server, a.token, instanceID.String(), validReportBody(), nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	old := time.Now().UTC().Add(-time.Hour)
	s.Require().NoError(s.DB.Exec("UPDATE ccf_agent_instances SET last_seen_at = ? WHERE instance_id = ?", old, instanceID).Error)
	before, _ := s.instance(*a.agent.ID, instanceID)

	rec = s.heartbeat(a.token, instanceID, nil, nil)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	after, ok := s.instance(*a.agent.ID, instanceID)
	s.Require().True(ok)
	s.True(after.LastSeenAt.After(before.LastSeenAt.Add(30*time.Minute)), "last_seen_at refreshed")
	s.Equal(before.ReportedStatus, after.ReportedStatus)
	s.Equal(before.Mode, after.Mode)
	s.Equal(before.EffectiveDigest, after.EffectiveDigest)
	s.Nil(after.HeartbeatConfigDigest)
	s.Nil(after.HeartbeatConfigRevision)
	s.Require().NotNil(after.ReportedAt)
	s.WithinDuration(*before.ReportedAt, *after.ReportedAt, time.Millisecond)
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
