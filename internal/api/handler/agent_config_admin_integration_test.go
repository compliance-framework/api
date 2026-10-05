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
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

// Integration tests for the admin agent-configuration routes (LLD A4) and the re-guarded
// /admin/agents routes (A2.7, R40), against Postgres.

const (
	acaVendorPlugin = "ghcr.io/vendor/ssh:v1"
	acaVendorPolicy = "ghcr.io/vendor/ssh-policies:v1"
	acaDigest       = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	acaOtherDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

func TestAgentConfigAdminAPI(t *testing.T) {
	suite.Run(t, new(AgentConfigAdminIntegrationSuite))
}

type AgentConfigAdminIntegrationSuite struct {
	tests.IntegrationTestSuite
	logger *zap.SugaredLogger
	server *api.Server // builtin PDP
	svc    *agentcfg.Service
	agent  *relational.Agent
	token  string // the suite's dummy (password) user: admin under builtin
}

func (s *AgentConfigAdminIntegrationSuite) SetupSuite() {
	s.IntegrationTestSuite.SetupSuite()
	s.logger = zap.NewNop().Sugar()
}

func (s *AgentConfigAdminIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
	s.server = s.newServer(nil)
	s.svc = agentcfg.NewService(s.DB, agentcfg.Settings{}, nil)
	agent, err := s.CreateAgent("config-agent")
	s.Require().NoError(err)
	s.agent = agent
	token, err := s.GetAuthToken()
	s.Require().NoError(err)
	s.token = *token
}

// newServer builds an API server; a nil PEP means the builtin PDP (RegisterHandlers' default).
func (s *AgentConfigAdminIntegrationSuite) newServer(pep *middleware.PEP) *api.Server {
	metrics := api.NewMetricsHandler(context.Background(), s.logger)
	srv := api.NewServer(context.Background(), s.logger, s.Config, metrics)
	RegisterHandlers(srv, s.logger, s.DB, s.Config, &APIServices{PEP: pep})
	return srv
}

// cedarServer builds a server enforcing through the embedded Cedar PDP. Roles are read from
// ccf_role_assignments behind a per-PDP cache, so create the role rows first.
func (s *AgentConfigAdminIntegrationSuite) cedarServer() *api.Server {
	pdp, err := authz.Open(authz.Options{Driver: authz.DriverCedar}, authz.Deps{DB: s.DB, Config: s.Config, Logger: s.logger})
	s.Require().NoError(err)
	return s.newServer(middleware.NewPEP(pdp, authz.FailClosed, s.logger))
}

// userToken creates a user (optionally with a manual role row) and returns a signed JWT.
func (s *AgentConfigAdminIntegrationSuite) userToken(email, authMethod, role string) (relational.User, string) {
	user := relational.User{Email: email, FirstName: "Test", LastName: "User", AuthMethod: authMethod}
	s.Require().NoError(s.DB.Create(&user).Error)
	if role != "" {
		s.Require().NoError(s.DB.Create(&relational.CCFRoleAssignment{
			RoleName:     role,
			AssigneeType: relational.RoleAssigneeTypeUser,
			AssigneeID:   relational.NormalizeAssigneeID(email),
			Source:       relational.RoleAssignmentSourceManual,
		}).Error)
	}
	token, err := authn.GenerateJWTToken(&user, s.Config.JWTPrivateKey)
	s.Require().NoError(err)
	return user, *token
}

// ---- request helpers ----

// send serves one request. body is sent raw (nil = no body); headers are key/value pairs and
// override the default Content-Type (application/json whenever a body is sent).
func (s *AgentConfigAdminIntegrationSuite) send(srv *api.Server, token, method, path string, body []byte, headers ...string) *httptest.ResponseRecorder {
	s.Require().Zero(len(headers)%2, "headers must be key/value pairs")
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	srv.E().ServeHTTP(rec, req)
	return rec
}

// call sends as the dummy user through the builtin server.
func (s *AgentConfigAdminIntegrationSuite) call(method, path string, body []byte, headers ...string) *httptest.ResponseRecorder {
	return s.send(s.server, s.token, method, path, body, headers...)
}

func (s *AgentConfigAdminIntegrationSuite) agentPath(agentID uuid.UUID, suffix string) string {
	return "/api/admin/agents/" + agentID.String() + suffix
}

func (s *AgentConfigAdminIntegrationSuite) path(suffix string) string {
	return s.agentPath(*s.agent.ID, suffix)
}

// putBody wraps a raw overlay in the PUT envelope.
func acaPutBody(overlay string) []byte {
	return []byte(`{"overlay":` + overlay + `}`)
}

// put saves overlay through srv as token; ifMatch "" omits the header.
func (s *AgentConfigAdminIntegrationSuite) put(srv *api.Server, token, ifMatch, overlay string) *httptest.ResponseRecorder {
	var headers []string
	if ifMatch != "" {
		headers = []string{"If-Match", ifMatch}
	}
	return s.send(srv, token, http.MethodPut, s.path("/config"), acaPutBody(overlay), headers...)
}

// save PUTs overlay as the dummy user and requires a 201 with the expected revision.
func (s *AgentConfigAdminIntegrationSuite) save(ifMatch, overlay string, wantRev int64) {
	rec := s.put(s.server, s.token, ifMatch, overlay)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	s.Require().Equal(agentconfig.AdminETag(wantRev), rec.Header().Get("ETag"))
}

type acaErrors struct {
	Errors map[string]json.RawMessage `json:"errors"`
}

func (s *AgentConfigAdminIntegrationSuite) errorsOf(rec *httptest.ResponseRecorder) map[string]json.RawMessage {
	var body acaErrors
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	s.Require().NotNil(body.Errors, rec.Body.String())
	return body.Errors
}

func (s *AgentConfigAdminIntegrationSuite) errorBody(rec *httptest.ResponseRecorder) string {
	var msg string
	s.Require().NoError(json.Unmarshal(s.errorsOf(rec)["body"], &msg), rec.Body.String())
	return msg
}

// validationErrors decodes a 422 body.
type acaValidationErrors struct {
	Body      string                     `json:"body"`
	Overlay   []agentconfig.FieldError   `json:"overlay"`
	Instances []instanceValidationErrors `json:"instances"`
}

func (s *AgentConfigAdminIntegrationSuite) unprocessable(rec *httptest.ResponseRecorder) acaValidationErrors {
	s.Require().Equal(http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	var body struct {
		Errors acaValidationErrors `json:"errors"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	s.Equal("configuration overlay is invalid", body.Errors.Body)
	// Slices are always present ([]), never null.
	raw := s.errorsOf(rec)
	for _, k := range []string{"overlay", "instances"} {
		s.True(strings.HasPrefix(string(raw[k]), "["), "%s must be a JSON array: %s", k, raw[k])
	}
	return body.Errors
}

func (s *AgentConfigAdminIntegrationSuite) revisionCount(agentID uuid.UUID) int64 {
	var n int64
	s.Require().NoError(s.DB.Model(&relational.AgentConfigRevision{}).Where("agent_id = ?", agentID).Count(&n).Error)
	return n
}

func acaData[T any](s *AgentConfigAdminIntegrationSuite, rec *httptest.ResponseRecorder) T {
	var out GenericDataResponse[T]
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return out.Data
}

// ---- instance helpers ----

func acaI64(v int64) *int64 { return &v }

// acaBase returns a reported base (redacted as the agent does: Redact clears the client secret) in the given mode with the vendor ssh plugin
// plus any extra plugins.
func acaBase(mode string, extra map[string]*agentconfig.Plugin) json.RawMessage {
	schedule := "* * * * *"
	plugins := map[string]*agentconfig.Plugin{
		"ssh": {
			Source:   acaVendorPlugin,
			Schedule: &schedule,
			Policies: []string{acaVendorPolicy},
			Config:   map[string]string{"host": "localhost"},
		},
	}
	for k, v := range extra {
		plugins[k] = v
	}
	cfg := agentconfig.Config{
		Daemon: true,
		API: &agentconfig.APIConfig{
			URL:  "http://api:8080",
			Auth: &agentconfig.APIAuth{ClientID: uuid.NewString()}, // redacted: no client secret
		},
		RemoteConfig: &agentconfig.RemoteConfig{Mode: mode},
		Plugins:      plugins,
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	return raw
}

// report stores a config report for a new instance of agentID and returns its instance id.
func (s *AgentConfigAdminIntegrationSuite) report(agentID uuid.UUID, mode string, mutate func(*agentconfig.Report)) uuid.UUID {
	instanceID := uuid.New()
	base := acaBase(mode, nil)
	r := agentconfig.Report{
		Hostname:        "host-" + instanceID.String()[:8],
		AgentVersion:    "v1.0.0",
		Mode:            mode,
		Daemon:          true,
		Status:          agentconfig.StatusApplied,
		Base:            base,
		Effective:       base,
		EffectiveDigest: acaDigest,
		RemoteConfig:    &agentconfig.RemoteConfig{Mode: mode},
	}
	if mode == agentconfig.ModeReport {
		r.Status = agentconfig.StatusNotApplicable
	}
	if mutate != nil {
		mutate(&r)
	}
	s.Require().NoError(s.svc.UpsertReport(context.Background(), agentID, nil, instanceID, r))
	return instanceID
}

// makeStale moves an instance's last_seen_at (and reported_at) into the past.
func (s *AgentConfigAdminIntegrationSuite) makeStale(instanceID uuid.UUID, age time.Duration) {
	at := time.Now().UTC().Add(-age)
	s.Require().NoError(s.DB.Exec(
		"UPDATE ccf_agent_instances SET last_seen_at = ?, reported_at = ? WHERE instance_id = ?", at, at, instanceID,
	).Error)
}

// ---- GET /config ----

func (s *AgentConfigAdminIntegrationSuite) TestGetConfigRevisionZero() {
	rec := s.call(http.MethodGet, s.path("/config"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(`"0"`, rec.Header().Get("ETag"))

	var body struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	s.JSONEq(`"`+s.agent.ID.String()+`"`, string(body.Data["agent-id"]))
	s.JSONEq(`0`, string(body.Data["revision"]))
	s.JSONEq(`{}`, string(body.Data["overlay"]))
	s.JSONEq(`null`, string(body.Data["comment"]))
	s.JSONEq(`null`, string(body.Data["created-at"]))
	s.JSONEq(`null`, string(body.Data["revert-of"]))
}

func (s *AgentConfigAdminIntegrationSuite) TestGetConfigAfterSave() {
	overlay := `{"verbosity":2,"plugins":{"ssh":{"labels":{"env":"prod"}}}}`
	s.save(`"0"`, overlay, 1)

	rec := s.call(http.MethodGet, s.path("/config"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(`"1"`, rec.Header().Get("ETag"))
	got := acaData[agentConfigRevisionResponse](s, rec)
	s.Equal(int64(1), got.Revision)
	s.JSONEq(overlay, string(got.Overlay))
	s.Require().NotNil(got.CreatedBy)
	s.Equal("dummy@example.com", *got.CreatedBy)
}

// The PUT response shows the stored revision: the same overlay bytes and size as GET and
// the revision list.
func (s *AgentConfigAdminIntegrationSuite) TestPutResponseMatchesReads() {
	rec := s.put(s.server, s.token, `"0"`, `{"verbosity":1}`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	put := acaData[agentConfigRevisionResponse](s, rec)

	rec = s.call(http.MethodGet, s.path("/config"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	get := acaData[agentConfigRevisionResponse](s, rec)
	s.Equal(get.OverlaySize, put.OverlaySize)
	s.Equal(string(get.Overlay), string(put.Overlay))

	rec = s.call(http.MethodGet, s.path("/config/revisions"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var list struct {
		Data []agentConfigRevisionResponse `json:"data"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
	s.Require().Len(list.Data, 1)
	s.Equal(put.OverlaySize, list.Data[0].OverlaySize)
}

func (s *AgentConfigAdminIntegrationSuite) TestGetConfigBadAndUnknownAgent() {
	rec := s.call(http.MethodGet, "/api/admin/agents/not-a-uuid/config", nil)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	rec = s.call(http.MethodGet, s.agentPath(uuid.New(), "/config"), nil)
	s.Equal(http.StatusNotFound, rec.Code, rec.Body.String())
}

// ---- PUT /config: revisions and concurrency ----

func (s *AgentConfigAdminIntegrationSuite) TestPutRevisionFlow() {
	// No If-Match => 428.
	rec := s.put(s.server, s.token, "", `{"verbosity":1}`)
	s.Require().Equal(http.StatusPreconditionRequired, rec.Code, rec.Body.String())
	s.Equal("If-Match header with the current revision is required", s.errorBody(rec))

	// First save with "0" => 201 + ETag "1".
	rec = s.put(s.server, s.token, `"0"`, `{"verbosity":1}`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	s.Equal(`"1"`, rec.Header().Get("ETag"))
	created := acaData[agentConfigRevisionResponse](s, rec)
	s.Equal(int64(1), created.Revision)
	s.JSONEq(`{"verbosity":1}`, string(created.Overlay))

	// Same (stale) If-Match with a different overlay => 409 with the current revision.
	rec = s.put(s.server, s.token, `"0"`, `{"verbosity":2}`)
	s.Require().Equal(http.StatusConflict, rec.Code, rec.Body.String())
	s.JSONEq(`{"errors":{"body":"configuration revision conflict","current-revision":1}}`, rec.Body.String())

	// Semantically identical overlay (different whitespace) with the current If-Match => 200, no row.
	rec = s.put(s.server, s.token, `"1"`, `{ "verbosity" : 1 }`)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(`"1"`, rec.Header().Get("ETag"))
	s.Equal(int64(1), acaData[agentConfigRevisionResponse](s, rec).Revision)
	s.Equal(int64(1), s.revisionCount(*s.agent.ID))

	// Weak and bare If-Match forms are accepted.
	rec = s.put(s.server, s.token, `W/"1"`, `{"verbosity":2}`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	rec = s.put(s.server, s.token, `2`, `{"verbosity":0}`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	s.Equal(int64(3), s.revisionCount(*s.agent.ID))

	// If-Match "*" and lists are not a revision => 428.
	rec = s.put(s.server, s.token, `*`, `{"verbosity":1}`)
	s.Equal(http.StatusPreconditionRequired, rec.Code, rec.Body.String())
}

func (s *AgentConfigAdminIntegrationSuite) TestPutWithComment() {
	body := []byte(`{"overlay":{"verbosity":1},"comment":"  raise verbosity  "}`)
	rec := s.call(http.MethodPut, s.path("/config"), body, "If-Match", `"0"`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	got := acaData[agentConfigRevisionResponse](s, rec)
	s.Require().NotNil(got.Comment)
	s.Equal("raise verbosity", *got.Comment)
}

// ---- PUT /config: overlay-level validation (422) ----

func (s *AgentConfigAdminIntegrationSuite) TestPutOverlayValidationErrors() {
	cases := []struct {
		name, overlay, path, code string
	}{
		{"locked key", `{"api":{}}`, "/api", agentconfig.FieldCodeLockedKey},
		{"non-string config value", `{"plugins":{"x":{"source":"ghcr.io/x/x:v1","config":{"port":2222}}}}`, "/plugins/x/config/port", agentconfig.FieldCodeInvalidType},
		{"unknown field", `{"foo":true}`, "/foo", agentconfig.FieldCodeUnknownField},
		{"policy_bundles is not a field", `{"policy_bundles":{"banner":{"modules":{}}}}`, "/policy_bundles", agentconfig.FieldCodeUnknownField},
		{"masked value", `{"plugins":{"ssh":{"config":{"password":"••••"}}}}`, "/plugins/ssh/config/password", agentconfig.FieldCodeMaskedValue},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			errs := s.unprocessable(s.put(s.server, s.token, `"0"`, tc.overlay))
			s.Require().NotEmpty(errs.Overlay)
			s.Equal(tc.path, errs.Overlay[0].Path)
			s.Equal(tc.code, errs.Overlay[0].Code)
			s.Empty(errs.Instances)
		})
	}
	s.Equal(int64(0), s.revisionCount(*s.agent.ID))
}

// ---- PUT /config: validation against instance bases (R14, R48) ----

func (s *AgentConfigAdminIntegrationSuite) TestPutValidatesAgainstFreshInstances() {
	fresh := s.report(*s.agent.ID, agentconfig.ModeApplySafe, nil)
	// A report-mode instance is never validated against.
	s.report(*s.agent.ID, agentconfig.ModeReport, nil)

	// A schedule-only patch of a plugin present in the fresh base => 201.
	s.save(`"0"`, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`, 1)

	// A new plugin without a source makes the merged config invalid for the fresh instance.
	errs := s.unprocessable(s.put(s.server, s.token, `"1"`, `{"plugins":{"newp":{"schedule":"* * * * *"}}}`))
	s.Empty(errs.Overlay)
	s.Require().Len(errs.Instances, 1)
	s.Equal(fresh.String(), errs.Instances[0].InstanceID)
	s.Require().NotNil(errs.Instances[0].Hostname)
	s.Require().NotEmpty(errs.Instances[0].Errors)
	s.Equal("/plugins/newp/source", errs.Instances[0].Errors[0].Path)
	s.Equal(agentconfig.FieldCodeRequired, errs.Instances[0].Errors[0].Code)
}

func (s *AgentConfigAdminIntegrationSuite) TestPutFallsBackToLatestStaleInstance() {
	// Only a stale apply-mode instance: it is still validated against (R48), so a plugin
	// without a source is rejected.
	older := s.report(*s.agent.ID, agentconfig.ModeApplySafe, nil)
	s.makeStale(older, 2*time.Hour)

	overlay := `{"plugins":{"other":{"schedule":"*/5 * * * *"}}}`
	errs := s.unprocessable(s.put(s.server, s.token, `"0"`, overlay))
	s.Require().Len(errs.Instances, 1)
	s.Equal(older.String(), errs.Instances[0].InstanceID)

	// A schedule-only patch of a plugin in the stale base is fine.
	s.save(`"0"`, `{"plugins":{"ssh":{"schedule":"*/10 * * * *"}}}`, 1)

	// A more recently reported (still stale) instance whose base defines "other" becomes the
	// only validation base, so the same overlay now saves.
	schedule := "@hourly"
	newer := s.report(*s.agent.ID, agentconfig.ModeApplyAll, func(r *agentconfig.Report) {
		base := acaBase(agentconfig.ModeApplyAll, map[string]*agentconfig.Plugin{
			"other": {Source: "ghcr.io/vendor/other:v1", Schedule: &schedule},
		})
		r.Base, r.Effective = base, base
	})
	s.makeStale(newer, time.Hour)
	s.save(`"1"`, overlay, 2)

	// Preview marks only the fallback instance as validated.
	rec := s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(overlay))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	preview := acaData[configPreviewResponse](s, rec)
	s.False(preview.Standalone)
	validated := map[string]bool{}
	for _, inst := range preview.Instances {
		s.True(inst.Stale, inst.InstanceID)
		validated[inst.InstanceID] = inst.Validated
	}
	s.Equal(map[string]bool{older.String(): false, newer.String(): true}, validated)
}

func (s *AgentConfigAdminIntegrationSuite) TestPutStandaloneWithoutInstances() {
	// With no reporting instance only overlay-level checks run, so a plugin without a source
	// saves (it cannot be merged against anything).
	s.save(`"0"`, `{"plugins":{"newp":{"schedule":"* * * * *"}}}`, 1)
}

// ---- PUT /config: request body handling ----

func (s *AgentConfigAdminIntegrationSuite) TestPutBodyHandling() {
	// Over the body limit => 413.
	big := []byte(`{"overlay":{"verbosity":1},"comment":"` + strings.Repeat("a", agentConfigBodyLimit) + `"}`)
	rec := s.call(http.MethodPut, s.path("/config"), big, "If-Match", `"0"`)
	s.Equal(http.StatusRequestEntityTooLarge, rec.Code)

	// An overlay over MaxOverlayBytes but within the body limit reaches validation => 422.
	oversized := fmt.Sprintf(`{"overlay":{"plugins":{"ssh":{"labels":{"a":%q}}}}}`, strings.Repeat("v", agentconfig.MaxOverlayBytes))
	errs := s.unprocessable(s.call(http.MethodPut, s.path("/config"), []byte(oversized), "If-Match", `"0"`))
	s.Require().NotEmpty(errs.Overlay)
	s.Equal(agentconfig.FieldCodeSize, errs.Overlay[0].Code)

	// A non-JSON media type => 415.
	rec = s.call(http.MethodPut, s.path("/config"), acaPutBody(`{"verbosity":1}`), "If-Match", `"0"`, echo.HeaderContentType, "text/plain")
	s.Equal(http.StatusUnsupportedMediaType, rec.Code, rec.Body.String())

	// Unknown envelope key => 400.
	rec = s.call(http.MethodPut, s.path("/config"), []byte(`{"overlay":{"verbosity":1},"note":"x"}`), "If-Match", `"0"`)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	// Missing overlay => 400.
	rec = s.call(http.MethodPut, s.path("/config"), []byte(`{"comment":"x"}`), "If-Match", `"0"`)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	// Comment over 2000 characters => 400.
	long := fmt.Sprintf(`{"overlay":{"verbosity":1},"comment":%q}`, strings.Repeat("é", maxRevisionCommentLen+1))
	rec = s.call(http.MethodPut, s.path("/config"), []byte(long), "If-Match", `"0"`)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	s.Equal(int64(0), s.revisionCount(*s.agent.ID))

	// application/json with parameters is accepted (R13).
	rec = s.call(http.MethodPut, s.path("/config"), acaPutBody(`{"verbosity":1}`), "If-Match", `"0"`, echo.HeaderContentType, "application/json; charset=utf-8")
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
}

// ---- Revert ----

func (s *AgentConfigAdminIntegrationSuite) TestRevert() {
	s.save(`"0"`, `{"verbosity":1}`, 1)
	s.save(`"1"`, `{"verbosity":2}`, 2)
	revert := s.path("/config/revisions/1/revert")

	// Missing If-Match => 428.
	rec := s.call(http.MethodPost, revert, nil)
	s.Require().Equal(http.StatusPreconditionRequired, rec.Code, rec.Body.String())

	// Stale If-Match => 409.
	rec = s.call(http.MethodPost, revert, nil, "If-Match", `"1"`)
	s.Require().Equal(http.StatusConflict, rec.Code, rec.Body.String())
	s.JSONEq(`{"errors":{"body":"configuration revision conflict","current-revision":2}}`, rec.Body.String())

	// Unknown revision => 404; non-numeric => 400.
	rec = s.call(http.MethodPost, s.path("/config/revisions/99/revert"), nil, "If-Match", `"2"`)
	s.Equal(http.StatusNotFound, rec.Code, rec.Body.String())
	rec = s.call(http.MethodPost, s.path("/config/revisions/abc/revert"), nil, "If-Match", `"2"`)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	// Empty body with the current If-Match => 201, revision 3, revert-of 1.
	rec = s.call(http.MethodPost, revert, nil, "If-Match", `"2"`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	s.Equal(`"3"`, rec.Header().Get("ETag"))
	got := acaData[agentConfigRevisionResponse](s, rec)
	s.Equal(int64(3), got.Revision)
	s.Require().NotNil(got.RevertOf)
	s.Equal(int64(1), *got.RevertOf)
	s.JSONEq(`{"verbosity":1}`, string(got.Overlay))

	// A revert with a comment body.
	rec = s.call(http.MethodPost, s.path("/config/revisions/2/revert"), []byte(`{"comment":"back to 2"}`), "If-Match", `"3"`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	got = acaData[agentConfigRevisionResponse](s, rec)
	s.Equal(int64(4), got.Revision)
	s.Require().NotNil(got.Comment)
	s.Equal("back to 2", *got.Comment)

	// Reverting to an overlay equal to the current one is a no-op (R14) => 200.
	rec = s.call(http.MethodPost, s.path("/config/revisions/2/revert"), nil, "If-Match", `"4"`)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(int64(4), s.revisionCount(*s.agent.ID))
}

// ---- Revisions ----

func (s *AgentConfigAdminIntegrationSuite) TestRevisions() {
	s.save(`"0"`, `{"verbosity":1}`, 1)
	s.save(`"1"`, `{"verbosity":2}`, 2)
	s.save(`"2"`, `{"verbosity":0}`, 3)

	rec := s.call(http.MethodGet, s.path("/config/revisions"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var raw map[string]json.RawMessage
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &raw))
	for _, k := range []string{"data", "total", "page", "limit", "totalPages"} {
		s.Contains(raw, k)
	}
	var items []map[string]json.RawMessage
	s.Require().NoError(json.Unmarshal(raw["data"], &items))
	s.Require().Len(items, 3)
	for i, item := range items {
		s.JSONEq(fmt.Sprint(3-i), string(item["revision"]), "newest first")
		s.NotContains(item, "overlay", "lists omit the overlay (R12)")
		s.Contains(item, "overlay-size")
	}
	s.JSONEq(`3`, string(raw["total"]))

	rec = s.call(http.MethodGet, s.path("/config/revisions?page=2&limit=1"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var page struct {
		Data       []agentConfigRevisionResponse `json:"data"`
		Total      int64                         `json:"total"`
		Page       int                           `json:"page"`
		Limit      int                           `json:"limit"`
		TotalPages int                           `json:"totalPages"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &page))
	s.Require().Len(page.Data, 1)
	s.Equal(int64(2), page.Data[0].Revision)
	s.Equal(int64(3), page.Total)
	s.Equal(2, page.Page)
	s.Equal(1, page.Limit)
	s.Equal(3, page.TotalPages)

	rec = s.call(http.MethodGet, s.path("/config/revisions?page=0"), nil)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	// One revision, with its overlay.
	rec = s.call(http.MethodGet, s.path("/config/revisions/2"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	got := acaData[agentConfigRevisionResponse](s, rec)
	s.Equal(int64(2), got.Revision)
	s.JSONEq(`{"verbosity":2}`, string(got.Overlay))

	rec = s.call(http.MethodGet, s.path("/config/revisions/99"), nil)
	s.Equal(http.StatusNotFound, rec.Code, rec.Body.String())
	rec = s.call(http.MethodGet, s.path("/config/revisions/abc"), nil)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
	rec = s.call(http.MethodGet, s.path("/config/revisions/0"), nil)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
}

func (s *AgentConfigAdminIntegrationSuite) TestRevisionsEmptyList() {
	rec := s.call(http.MethodGet, s.path("/config/revisions"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var raw map[string]json.RawMessage
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &raw))
	s.JSONEq(`[]`, string(raw["data"]))
	s.JSONEq(`0`, string(raw["total"]))
}

// ---- Preview ----

func (s *AgentConfigAdminIntegrationSuite) TestPreviewWillApply() {
	safe := s.report(*s.agent.ID, agentconfig.ModeApplySafe, nil)
	all := s.report(*s.agent.ID, agentconfig.ModeApplyAll, nil)
	reportOnly := s.report(*s.agent.ID, agentconfig.ModeReport, nil)
	s.save(`"0"`, `{"verbosity":1}`, 1)

	// A new plugin from an untrusted OCI source.
	overlay := `{"plugins":{"newp":{"source":"ghcr.io/other/newp:v1","schedule":"@hourly"}}}`
	rec := s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(overlay))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	preview := acaData[configPreviewResponse](s, rec)
	s.Equal(int64(1), preview.DesiredRevision)
	s.False(preview.Standalone)
	s.Empty(preview.OverlayErrors)

	byID := map[string]instancePreview{}
	for _, inst := range preview.Instances {
		byID[inst.InstanceID] = inst
	}
	s.Require().Len(byID, 3)

	p := byID[safe.String()]
	s.True(p.Validated)
	s.False(p.WillApply)
	s.Equal(agentconfig.ReasonUnsafeChanges, p.WillApplyReason)
	s.NotEmpty(p.Changes)
	s.NotEmpty(p.DiffVsCurrent)
	s.NotEmpty(p.Effective)

	p = byID[all.String()]
	s.True(p.Validated)
	s.True(p.WillApply)
	s.Empty(p.WillApplyReason)

	p = byID[reportOnly.String()]
	s.False(p.Validated, "report-mode instances are not validated against")
	s.False(p.WillApply)
	s.Equal(agentconfig.WillApplyReasonModeReport, p.WillApplyReason)

	// Nothing was saved.
	s.Equal(int64(1), s.revisionCount(*s.agent.ID))
}

func (s *AgentConfigAdminIntegrationSuite) TestPreviewStandaloneAndSlices() {
	rec := s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(`{"verbosity":1}`))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.JSONEq(`{"data":{"desired-revision":0,"standalone":true,"overlay-errors":[],"instances":[]}}`, rec.Body.String())

	// An unchanged overlay on a fresh instance: every slice is [] rather than null.
	s.report(*s.agent.ID, agentconfig.ModeApplySafe, nil)
	rec = s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(`{}`))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Data struct {
			Standalone bool                         `json:"standalone"`
			Instances  []map[string]json.RawMessage `json:"instances"`
		} `json:"data"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	s.False(body.Data.Standalone)
	s.Require().Len(body.Data.Instances, 1)
	inst := body.Data.Instances[0]
	for _, k := range []string{"diff-vs-current", "errors", "warnings", "changes"} {
		s.JSONEq(`[]`, string(inst[k]), k)
	}
	s.JSONEq(`true`, string(inst["will-apply"]))
	s.NotContains(inst, "will-apply-reason")
}

func (s *AgentConfigAdminIntegrationSuite) TestPreviewInvalidOverlay() {
	s.report(*s.agent.ID, agentconfig.ModeApplySafe, nil)
	s.report(*s.agent.ID, agentconfig.ModeApplyAll, nil)

	rec := s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(`{"api":{"url":"http://evil"}}`))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	preview := acaData[configPreviewResponse](s, rec)
	s.Require().NotEmpty(preview.OverlayErrors)
	s.Equal("/api", preview.OverlayErrors[0].Path)
	s.Equal(agentconfig.FieldCodeLockedKey, preview.OverlayErrors[0].Code)
	s.NotNil(preview.Instances)
	s.Empty(preview.Instances, "an invalid overlay is not previewed per instance")
	s.Contains(rec.Body.String(), `"instances":[]`)

	// Over MaxOverlayBytes (but within the body limit): overlay errors only.
	big := `{"plugins":{"ssh":{"labels":{"x":"` + strings.Repeat("a", agentconfig.MaxOverlayBytes) + `"}}}}`
	rec = s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(big))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	preview = acaData[configPreviewResponse](s, rec)
	s.Require().NotEmpty(preview.OverlayErrors)
	s.Equal(agentconfig.FieldCodeSize, preview.OverlayErrors[0].Code)
	s.Empty(preview.Instances)

	// Instance-level errors (no source) also force invalid-config, and are listed per instance.
	rec = s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(`{"plugins":{"newp":{"schedule":"* * * * *"}}}`))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	preview = acaData[configPreviewResponse](s, rec)
	s.Empty(preview.OverlayErrors)
	for _, inst := range preview.Instances {
		s.NotEmpty(inst.Errors)
		s.Equal(agentconfig.ReasonInvalidConfig, inst.WillApplyReason)
	}

	// Body problems are still 400 / 415.
	rec = s.call(http.MethodPost, s.path("/config/preview"), []byte(`{"overlay":{},"x":1}`))
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
	rec = s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(`{}`), echo.HeaderContentType, "text/plain")
	s.Equal(http.StatusUnsupportedMediaType, rec.Code, rec.Body.String())
}

// R59: errors already present in Merge(base, {}) come from the host file. They are
// non-blocking warnings; only errors the overlay introduces block a save or force
// invalid-config.
func (s *AgentConfigAdminIntegrationSuite) TestFileOriginErrorsDoNotBlock() {
	badCron := "not a cron"
	instance := s.report(*s.agent.ID, agentconfig.ModeApplySafe, func(r *agentconfig.Report) {
		base := acaBase(agentconfig.ModeApplySafe, map[string]*agentconfig.Plugin{
			"x": {Source: acaVendorPlugin, Schedule: &badCron},
		})
		r.Base, r.Effective = base, base
	})

	// An unrelated overlay saves.
	s.save(`"0"`, `{"verbosity":1}`, 1)

	// Preview shows the file error as a warning and the instance still applies.
	rec := s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(`{"verbosity":2}`))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	preview := acaData[configPreviewResponse](s, rec)
	s.Require().Len(preview.Instances, 1)
	p := preview.Instances[0]
	s.Equal(instance.String(), p.InstanceID)
	s.True(p.Validated)
	s.Empty(p.Errors)
	s.NotNil(p.Errors)
	s.Require().Len(p.Warnings, 1)
	s.Equal("/plugins/x/schedule", p.Warnings[0].Path)
	s.Equal(agentconfig.FieldCodeCron, p.Warnings[0].Code)
	s.True(p.WillApply)
	s.Empty(p.WillApplyReason)

	// A new bad cron in the overlay is still refused (caught on the overlay itself).
	rec = s.put(s.server, s.token, `"1"`, `{"plugins":{"ssh":{"schedule":"also bad"}}}`)
	body := s.unprocessable(rec)
	s.Require().NotEmpty(body.Overlay)
	s.Equal("/plugins/ssh/schedule", body.Overlay[0].Path)

	// An error that only appears once merged is introduced: 422, listed per instance with
	// the file-origin error as a warning.
	rec = s.put(s.server, s.token, `"1"`, `{"plugins":{"newp":{"schedule":"* * * * *"}}}`)
	body = s.unprocessable(rec)
	s.Empty(body.Overlay)
	s.Require().Len(body.Instances, 1)
	s.Require().NotEmpty(body.Instances[0].Errors)
	s.Equal("/plugins/newp/source", body.Instances[0].Errors[0].Path)
	s.Require().Len(body.Instances[0].Warnings, 1)
	s.Equal("/plugins/x/schedule", body.Instances[0].Warnings[0].Path)

	// Preview agrees: an introduced error forces invalid-config.
	rec = s.call(http.MethodPost, s.path("/config/preview"), acaPutBody(`{"plugins":{"newp":{"schedule":"* * * * *"}}}`))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	preview = acaData[configPreviewResponse](s, rec)
	s.Require().Len(preview.Instances, 1)
	s.False(preview.Instances[0].WillApply)
	s.Equal(agentconfig.ReasonInvalidConfig, preview.Instances[0].WillApplyReason)
	s.Equal(int64(1), s.revisionCount(*s.agent.ID))
}

// ---- Instances ----

func (s *AgentConfigAdminIntegrationSuite) TestInstances() {
	ctx := context.Background()
	agentID := *s.agent.ID

	// Desired revision 1.
	s.save(`"0"`, `{"verbosity":1}`, 1)

	inSync := s.report(agentID, agentconfig.ModeApplySafe, func(r *agentconfig.Report) {
		r.AppliedRevision = acaI64(1)
		r.Plugins = []agentconfig.PluginReport{{Name: "ssh", Source: acaVendorPlugin, LibVersion: "v0.7.1"}, {Name: "local"}}
	})
	pending := s.report(agentID, agentconfig.ModeApplySafe, nil) // applied nil, attempted nil
	rejected := s.report(agentID, agentconfig.ModeApplyAll, func(r *agentconfig.Report) {
		r.AttemptedRevision = acaI64(1)
		r.Status = agentconfig.StatusRejected
		r.Reason = agentconfig.ReasonDownloadFailed
	})
	s.makeStale(rejected, time.Hour)
	reportOnly := s.report(agentID, agentconfig.ModeReport, nil)
	heartbeatOnly := uuid.New()
	digest := acaDigest
	s.Require().NoError(s.svc.TouchFromHeartbeat(ctx, agentID, nil, heartbeatOnly, acaI64(0), &digest))
	// A newer heartbeat digest than the reported one marks the report stale.
	other := acaOtherDigest
	s.Require().NoError(s.svc.TouchFromHeartbeat(ctx, agentID, nil, inSync, acaI64(1), &other))

	// Another agent's instance never shows up.
	otherAgent, err := s.CreateAgent("other-agent")
	s.Require().NoError(err)
	foreign := s.report(*otherAgent.ID, agentconfig.ModeApplySafe, nil)

	rec := s.call(http.MethodGet, s.path("/instances"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var list agentInstanceListResponse
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
	s.Equal(int64(1), list.Meta.DesiredRevision)
	s.Equal(agentInstanceCounts{
		Total: 5, Fresh: 4, Stale: 1,
		InSync: 1, OutOfSync: 2,
		Pending: 1, Rejected: 1, Failed: 0, Unknown: 1,
	}, list.Meta.Counts)

	byID := map[string]agentInstanceSummary{}
	for _, inst := range list.Data {
		byID[inst.InstanceID] = inst
	}
	s.NotContains(byID, foreign.String())

	st := byID[inSync.String()]
	s.Equal(agentconfig.StatusApplied, st.Status)
	s.Equal(agentcfg.SyncInSync, st.SyncStatus)
	s.True(st.ReportStale)
	s.Equal([]agentconfig.PluginReport{{Name: "ssh", Source: acaVendorPlugin, LibVersion: "v0.7.1"}, {Name: "local"}}, st.Plugins, "R76: listed with the summary")
	s.Require().NotNil(st.HeartbeatConfigRevision)
	s.Equal(int64(1), *st.HeartbeatConfigRevision)
	s.NotEmpty(st.RemoteConfig)

	st = byID[pending.String()]
	s.Equal([]agentconfig.PluginReport{}, st.Plugins, "an agent that does not report plugins")
	s.Equal(agentconfig.StatusPending, st.Status)
	s.Equal(agentcfg.SyncOutOfSync, st.SyncStatus)
	s.False(st.Stale)

	st = byID[rejected.String()]
	s.Equal(agentconfig.StatusRejected, st.Status)
	s.True(st.Stale)
	s.Require().NotNil(st.Reason)
	s.Equal(agentconfig.ReasonDownloadFailed, *st.Reason)

	st = byID[reportOnly.String()]
	s.Equal(agentconfig.StatusNotApplicable, st.Status)
	s.Equal(agentcfg.SyncNotApplicable, st.SyncStatus)

	st = byID[heartbeatOnly.String()]
	s.Equal(agentconfig.StatusUnknown, st.Status)
	s.Equal(agentcfg.SyncUnknown, st.SyncStatus)
	s.Nil(st.ReportedAt)

	// Summaries carry [] for list fields and no base/effective.
	var rawList struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &rawList))
	for _, item := range rawList.Data {
		s.NotContains(item, "base")
		s.NotContains(item, "effective")
		for _, k := range []string{"unsafe", "warnings"} {
			s.JSONEq(`[]`, string(item[k]), k)
		}
		s.NotContains(item, "policy-errors")
		s.Contains(item, "plugins")
	}

	// Detail: base and effective.
	rec = s.call(http.MethodGet, s.path("/instances/"+inSync.String()), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	detail := acaData[agentInstanceDetail](s, rec)
	s.Equal(inSync.String(), detail.InstanceID)
	s.Contains(string(detail.Base), acaVendorPlugin)
	s.Contains(string(detail.Effective), acaVendorPolicy)
	s.Equal([]agentconfig.PluginReport{{Name: "ssh", Source: acaVendorPlugin, LibVersion: "v0.7.1"}, {Name: "local"}}, detail.Plugins, "R76")

	// A heartbeat-only instance has null configs and [] plugins.
	rec = s.call(http.MethodGet, s.path("/instances/"+heartbeatOnly.String()), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var rawDetail struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &rawDetail))
	s.JSONEq(`null`, string(rawDetail.Data["base"]))
	s.NotContains(rawDetail.Data, "policy-bundles")
	s.JSONEq(`[]`, string(rawDetail.Data["plugins"]))

	// Another agent's instance => 404; a bad instance id => 400.
	rec = s.call(http.MethodGet, s.path("/instances/"+foreign.String()), nil)
	s.Equal(http.StatusNotFound, rec.Code, rec.Body.String())
	rec = s.call(http.MethodGet, s.path("/instances/not-a-uuid"), nil)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
}

func (s *AgentConfigAdminIntegrationSuite) TestInstancesEmpty() {
	rec := s.call(http.MethodGet, s.path("/instances"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.JSONEq(`{"data":[],"meta":{"desired-revision":0,"counts":{"total":0,"fresh":0,"stale":0,"in-sync":0,"out-of-sync":0,"pending":0,"rejected":0,"failed":0,"unknown":0}}}`, rec.Body.String())
}

// ---- Agent deletion ----

// Deleting an agent removes its instances and its revisions (the purge path for an overlay
// that held a secret); other agents' revisions are kept.
func (s *AgentConfigAdminIntegrationSuite) TestDeleteAgentRemovesInstancesAndRevisions() {
	other, err := s.CreateAgent("other-agent")
	s.Require().NoError(err)
	s.report(*s.agent.ID, agentconfig.ModeApplySafe, nil)
	s.report(*s.agent.ID, agentconfig.ModeReport, nil)
	s.save(`"0"`, `{"verbosity":1}`, 1)
	s.save(`"1"`, `{"plugins":{"ssh":{"config":{"password":"hunter2"}}}}`, 2)
	rec := s.send(s.server, s.token, http.MethodPut, s.agentPath(*other.ID, "/config"), acaPutBody(`{"verbosity":1}`), "If-Match", `"0"`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	rec = s.call(http.MethodDelete, s.path(""), nil)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	var instances int64
	s.Require().NoError(s.DB.Model(&relational.AgentInstance{}).Where("agent_id = ?", *s.agent.ID).Count(&instances).Error)
	s.Zero(instances)
	s.Zero(s.revisionCount(*s.agent.ID))
	s.Equal(int64(1), s.revisionCount(*other.ID))

	// The (soft-deleted) agent is gone for the config routes.
	rec = s.call(http.MethodGet, s.path("/config"), nil)
	s.Equal(http.StatusNotFound, rec.Code, rec.Body.String())
}

// ---- Builtin authz (R39) ----

func (s *AgentConfigAdminIntegrationSuite) TestBuiltinSSOUserNeedsAdminGroup() {
	original := s.Config.SSO
	s.Config.SSO = &config.SSOConfig{
		Enabled: true,
		Providers: map[string]config.SSOProviderConfig{
			"test": {Name: "test", RequiredAdminGroups: []string{"ccf-admins"}},
		},
	}
	defer func() { s.Config.SSO = original }()

	ssoToken := func(email string, groups []string) string {
		user, token := s.userToken(email, "sso", "")
		s.Require().NoError(s.DB.Create(&relational.SSOUserLink{
			UserID:     user.ID.String(),
			Provider:   "test",
			ExternalID: email,
			Email:      email,
			Groups:     sso.SerializeStringArray(groups),
			LastSync:   time.Now(),
		}).Error)
		return token
	}
	member := ssoToken("sso-member@example.com", []string{"developers"})
	admin := ssoToken("sso-admin@example.com", []string{"ccf-admins"})

	denied := []struct {
		method, path string
		body         []byte
		headers      []string
	}{
		{http.MethodGet, "/api/admin/agents", nil, nil},
		{http.MethodGet, s.path(""), nil, nil},
		{http.MethodGet, s.path("/config"), nil, nil},
		{http.MethodPut, s.path("/config"), acaPutBody(`{"verbosity":1}`), []string{"If-Match", `"0"`}},
		{http.MethodPost, s.path("/config/preview"), acaPutBody(`{"verbosity":1}`), nil},
		{http.MethodGet, s.path("/config/revisions"), nil, nil},
		{http.MethodGet, s.path("/instances"), nil, nil},
	}
	for _, tc := range denied {
		rec := s.send(s.server, member, tc.method, tc.path, tc.body, tc.headers...)
		s.Equal(http.StatusForbidden, rec.Code, "%s %s: %s", tc.method, tc.path, rec.Body.String())
	}

	// An SSO user in the admin group and the password user are allowed.
	for _, token := range []string{admin, s.token} {
		rec := s.send(s.server, token, http.MethodGet, "/api/admin/agents", nil)
		s.Equal(http.StatusOK, rec.Code, rec.Body.String())
		rec = s.send(s.server, token, http.MethodGet, s.path("/config"), nil)
		s.Equal(http.StatusOK, rec.Code, rec.Body.String())
	}
	rec := s.send(s.server, admin, http.MethodPut, s.path("/config"), acaPutBody(`{"verbosity":1}`), "If-Match", `"0"`)
	s.Equal(http.StatusCreated, rec.Code, rec.Body.String())
	s.Equal(int64(1), s.revisionCount(*s.agent.ID))
}

// ---- Cedar authz (R40) ----

func (s *AgentConfigAdminIntegrationSuite) TestCedarViewer() {
	_, viewer := s.userToken("viewer@example.com", "", "viewer")
	srv := s.cedarServer()

	allowed := []struct{ method, path string }{
		{http.MethodGet, "/api/admin/agents"},
		{http.MethodGet, s.path("")},
		{http.MethodGet, s.path("/config")},
		{http.MethodGet, s.path("/config/revisions")},
		{http.MethodGet, s.path("/instances")},
	}
	for _, tc := range allowed {
		rec := s.send(srv, viewer, tc.method, tc.path, nil)
		s.Equal(http.StatusOK, rec.Code, "%s %s: %s", tc.method, tc.path, rec.Body.String())
	}

	denied := []struct {
		method, path string
		body         []byte
		headers      []string
	}{
		{http.MethodPost, s.path("/config/preview"), acaPutBody(`{"verbosity":1}`), nil},
		{http.MethodPut, s.path("/config"), acaPutBody(`{"verbosity":1}`), []string{"If-Match", `"0"`}},
		{http.MethodPost, s.path("/config/revisions/1/revert"), nil, []string{"If-Match", `"0"`}},
		{http.MethodPost, "/api/admin/agents", []byte(`{"name":"viewer-agent"}`), nil},
		{http.MethodPut, s.path(""), []byte(`{"name":"renamed"}`), nil},
		{http.MethodDelete, s.path(""), nil, nil},
		{http.MethodGet, s.path("/keys"), nil, nil},
		{http.MethodPost, s.path("/keys"), []byte(`{"never-expires":true}`), nil},
	}
	for _, tc := range denied {
		rec := s.send(srv, viewer, tc.method, tc.path, tc.body, tc.headers...)
		s.Equal(http.StatusForbidden, rec.Code, "%s %s: %s", tc.method, tc.path, rec.Body.String())
	}
	s.Equal(int64(0), s.revisionCount(*s.agent.ID))
}

// Overlays are verbatim for agent:configure holders and redacted for read-only callers.
func (s *AgentConfigAdminIntegrationSuite) TestCedarOverlayRedactedForReaders() {
	overlay := `{"plugins":{"ssh":{"config":{"password":"hunter2","host":"db","pass_ref":"${env:SSH_PASS}"},"policy_data":{"api_token":"t0k3n","threshold":3}}}}`
	s.save(`"0"`, overlay, 1)
	_, viewer := s.userToken("viewer@example.com", "", "viewer")
	_, contributor := s.userToken("contributor@example.com", "", "contributor")
	_, admin := s.userToken("cedar-admin@example.com", "", "admin")
	srv := s.cedarServer()

	redacted := `{"plugins":{"ssh":{"config":{"password":"••••","host":"db","pass_ref":"${env:SSH_PASS}"},"policy_data":{"api_token":"••••","threshold":3}}}}`
	for _, path := range []string{s.path("/config"), s.path("/config/revisions/1")} {
		for _, token := range []string{viewer, contributor} {
			rec := s.send(srv, token, http.MethodGet, path, nil)
			s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
			got := acaData[agentConfigRevisionResponse](s, rec)
			s.JSONEq(redacted, string(got.Overlay), path)
			s.NotContains(rec.Body.String(), "hunter2", path)
			s.NotContains(rec.Body.String(), "t0k3n", path)
		}
		rec := s.send(srv, admin, http.MethodGet, path, nil)
		s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
		got := acaData[agentConfigRevisionResponse](s, rec)
		s.JSONEq(overlay, string(got.Overlay), "a configure holder gets the literal overlay: %s", path)
	}
}

// configureFailsPDP allows everything except agent:configure, which is unavailable.
type configureFailsPDP struct{}

func (configureFailsPDP) Evaluate(_ context.Context, _ authz.Subject, action string, _ authz.Resource, _ map[string]any) (authz.Decision, error) {
	if action == authz.ActionConfigure {
		return authz.Decision{}, authz.ErrUnavailable
	}
	return authz.Decision{Allow: true}, nil
}

func (p configureFailsPDP) Evaluations(ctx context.Context, reqs []authz.EvalRequest) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(reqs))
	for i, r := range reqs {
		d, err := p.Evaluate(ctx, r.Subject, r.Action, r.Resource, r.Context)
		if err != nil {
			return nil, err
		}
		out[i] = d
	}
	return out, nil
}

// When agent:configure cannot be evaluated, the overlay is redacted (fail closed), whatever
// the PEP's fail mode.
func (s *AgentConfigAdminIntegrationSuite) TestOverlayRedactedWhenConfigureCheckFails() {
	s.save(`"0"`, `{"plugins":{"ssh":{"config":{"password":"hunter2"}}}}`, 1)
	srv := s.newServer(middleware.NewPEP(configureFailsPDP{}, authz.FailOpen, s.logger))
	rec := s.send(srv, s.token, http.MethodGet, s.path("/config"), nil)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	got := acaData[agentConfigRevisionResponse](s, rec)
	s.JSONEq(`{"plugins":{"ssh":{"config":{"password":"••••"}}}}`, string(got.Overlay))
}

func (s *AgentConfigAdminIntegrationSuite) TestCedarAdminCanEditSchedule() {
	s.report(*s.agent.ID, agentconfig.ModeApplySafe, nil)
	_, admin := s.userToken("cedar-admin@example.com", "", "admin")
	srv := s.cedarServer()

	rec := s.put(srv, admin, `"0"`, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
}

func (s *AgentConfigAdminIntegrationSuite) TestCedarUserWithoutRoleDenied() {
	_, token := s.userToken("nobody@example.com", "", "")
	srv := s.cedarServer()
	rec := s.send(srv, token, http.MethodGet, s.path("/config"), nil)
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	rec = s.send(srv, token, http.MethodGet, "/api/admin/agents", nil)
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
}

// ---- CORS (R13) ----

func (s *AgentConfigAdminIntegrationSuite) TestCORSAllowsIfMatchAndExposesETag() {
	const origin = "http://ui.example.com"
	original := s.Config.APIAllowedOrigins
	s.Config.APIAllowedOrigins = []string{origin}
	defer func() { s.Config.APIAllowedOrigins = original }()
	srv := s.newServer(nil)

	rec := s.send(srv, "", http.MethodOptions, s.path("/config"), nil,
		echo.HeaderOrigin, origin,
		echo.HeaderAccessControlRequestMethod, http.MethodPut,
		echo.HeaderAccessControlRequestHeaders, "if-match",
	)
	s.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	s.Equal(origin, rec.Header().Get(echo.HeaderAccessControlAllowOrigin))
	s.Contains(strings.ToLower(rec.Header().Get(echo.HeaderAccessControlAllowHeaders)), "if-match")

	rec = s.send(srv, s.token, http.MethodGet, s.path("/config"), nil, echo.HeaderOrigin, origin)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(origin, rec.Header().Get(echo.HeaderAccessControlAllowOrigin))
	s.Contains(rec.Header().Get(echo.HeaderAccessControlExposeHeaders), "ETag")
	s.Equal(`"0"`, rec.Header().Get("ETag"))
}
