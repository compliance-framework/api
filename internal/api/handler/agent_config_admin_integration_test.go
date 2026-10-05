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

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
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

// ---- Revisions ----

// ---- Preview ----

// ---- Instances ----

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

// ---- Cedar authz (R40) ----

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
