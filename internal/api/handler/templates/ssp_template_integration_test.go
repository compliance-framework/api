//go:build integration

package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	handlerpkg "github.com/compliance-framework/api/internal/api/handler"
	templatehandlers "github.com/compliance-framework/api/internal/api/handler/templates"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/sspscope"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

// SSPTemplateApiIntegrationSuite exercises /admin/ssp-templates through the embedded
// Cedar PDP.
type SSPTemplateApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server      *api.Server
	admin       string
	contributor string
	runs        *recordingEnqueuer
}

func TestSSPTemplateApi(t *testing.T) {
	suite.Run(t, new(SSPTemplateApiIntegrationSuite))
}

func (s *SSPTemplateApiIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
	s.admin = s.roledUser("admin@example.com", "admin")
	s.contributor = s.roledUser("contributor@example.com", "contributor")
	s.runs = &recordingEnqueuer{}
	s.server = s.newServer(s.runs)
}

// newServer serves the API through the embedded Cedar PDP; runs may be nil.
func (s *SSPTemplateApiIntegrationSuite) newServer(runs templatehandlers.SSPTemplateRunEnqueuer) *api.Server {
	logger := zap.NewNop().Sugar()
	pdp, err := authz.Open(authz.Options{Driver: authz.DriverCedar}, authz.Deps{DB: s.DB, Config: s.Config, Logger: logger})
	s.Require().NoError(err)
	server := api.NewServer(context.Background(), logger, s.Config, api.NewMetricsHandler(context.Background(), logger))
	services := &handlerpkg.APIServices{PEP: middleware.NewPEP(pdp, authz.FailClosed, logger)}
	if runs != nil {
		services.SSPTemplateRunEnqueuer = runs
	}
	handlerpkg.RegisterHandlers(server, logger, s.DB, s.Config, services)
	return server
}

func (s *SSPTemplateApiIntegrationSuite) roledUser(email, role string) string {
	user := relational.User{Email: email, FirstName: "Test", LastName: "User"}
	s.Require().NoError(s.DB.Create(&user).Error)
	s.Require().NoError(s.DB.Create(&relational.CCFRoleAssignment{
		RoleName:     role,
		AssigneeType: relational.RoleAssigneeTypeUser,
		AssigneeID:   relational.NormalizeAssigneeID(email),
	}).Error)
	token, err := authn.GenerateJWTToken(&user, s.Config.JWTPrivateKey)
	s.Require().NoError(err)
	return *token
}

func (s *SSPTemplateApiIntegrationSuite) do(token, method, path string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		s.Require().NoError(err)
	}
	req := httptest.NewRequest(method, "/api/admin/ssp-templates"+path, bytes.NewReader(raw))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	rec := httptest.NewRecorder()
	s.server.E().ServeHTTP(rec, req)
	return rec
}

func templateBody(name string, keys ...string) map[string]any {
	return map[string]any{
		"name":           name,
		"keys":           keys,
		"title-template": "SSP for {{ ._app }}",
	}
}

// decode checks the status and decodes the JSON body.
func (s *SSPTemplateApiIntegrationSuite) decode(rec *httptest.ResponseRecorder, status int) map[string]any {
	s.Require().Equal(status, rec.Code, rec.Body.String())
	var out map[string]any
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

func (s *SSPTemplateApiIntegrationSuite) create(body map[string]any) map[string]any {
	return s.decode(s.do(s.admin, http.MethodPost, "", body), http.StatusCreated)["data"].(map[string]any)
}

func (s *SSPTemplateApiIntegrationSuite) TestAdminManagesTemplates() {
	profileID := uuid.New()
	s.Require().NoError(s.DB.Create(&relational.Profile{UUIDModel: relational.UUIDModel{ID: &profileID}}).Error)

	body := templateBody("Applications", "_APP")
	body["scope-labels"] = [][]string{{"Repo"}, {"region", "aws_account"}}
	body["filter"] = map[string]any{"scope": map[string]any{"condition": map[string]any{"label": "auto_create_ssp", "operator": "=", "value": "true"}}}
	body["props"] = []map[string]string{{"name": "application", "value": "{{ ._app }}"}}
	body["profile-ids"] = []uuid.UUID{profileID}
	body["enabled"] = false
	created := s.create(body)
	s.Equal([]any{"_app"}, created["keys"])
	s.Equal([]any{[]any{"repo"}, []any{"aws_account", "region"}}, created["scope-labels"])
	s.Equal(false, created["enabled"])
	s.Equal(float64(1), created["min-streams"])
	s.Equal([]any{profileID.String()}, created["profile-ids"])
	s.Contains(created, "created-at")
	s.Equal(float64(0), created["ssp-count"])
	s.Contains(created, "last-run-at")
	s.Nil(created["last-run-at"])
	s.NotNil(created["filter"])
	id := created["id"].(string)

	list := s.decode(s.do(s.admin, http.MethodGet, "", nil), http.StatusOK)
	s.Equal(float64(1), list["total"])
	s.Equal(id, list["data"].([]any)[0].(map[string]any)["id"])
	s.Equal(false, list["data"].([]any)[0].(map[string]any)["enabled"], "a disabled template is stored disabled")

	update := templateBody("Renamed", "_app")
	update["enabled"] = true
	update["min-streams"] = 3
	s.decode(s.do(s.admin, http.MethodPut, "/"+id, update), http.StatusOK)
	got := s.decode(s.do(s.admin, http.MethodGet, "/"+id, nil), http.StatusOK)["data"].(map[string]any)
	s.Equal("Renamed", got["name"])
	s.Equal(true, got["enabled"])
	s.Equal(float64(3), got["min-streams"])
	s.Nil(got["filter"])
	s.Equal([]any{}, got["profile-ids"])

	rec := s.do(s.admin, http.MethodPut, "/"+id, templateBody("Renamed", "_app", "region"))
	s.Equal(http.StatusBadRequest, rec.Code, "keys cannot change: %s", rec.Body.String())

	s.Equal(http.StatusNoContent, s.do(s.admin, http.MethodDelete, "/"+id, nil).Code)
	s.Equal(http.StatusNotFound, s.do(s.admin, http.MethodGet, "/"+id, nil).Code)
}

func (s *SSPTemplateApiIntegrationSuite) TestContributorDenied() {
	id := s.create(templateBody("Applications", "_app"))["id"].(string)
	for _, req := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "", nil},
		{http.MethodPost, "", templateBody("Other", "_app")},
		{http.MethodGet, "/" + id, nil},
		{http.MethodPut, "/" + id, templateBody("Other", "_app")},
		{http.MethodDelete, "/" + id, nil},
	} {
		rec := s.do(s.contributor, req.method, req.path, req.body)
		s.Equal(http.StatusForbidden, rec.Code, "%s %s", req.method, req.path)
	}
	var count int64
	s.Require().NoError(s.DB.Model(&relational.SSPTemplate{}).Count(&count).Error)
	s.Equal(int64(1), count)
}

func (s *SSPTemplateApiIntegrationSuite) TestErrors() {
	badTitle := templateBody("Apps", "_app")
	badTitle["title-template"] = "{{ ._app"
	unknownProfile := templateBody("Apps", "_app")
	unknownProfile["profile-ids"] = []string{uuid.NewString()}
	unknown := "/" + uuid.NewString()

	cases := []struct {
		name, method, path string
		body               any
		want               int
	}{
		{"unparseable title", http.MethodPost, "", badTitle, http.StatusBadRequest},
		{"unknown profile", http.MethodPost, "", unknownProfile, http.StatusBadRequest},
		{"bad id", http.MethodGet, "/nope", nil, http.StatusBadRequest},
		{"unknown get", http.MethodGet, unknown, nil, http.StatusNotFound},
		{"unknown update", http.MethodPut, unknown, templateBody("Apps", "_app"), http.StatusNotFound},
		{"unknown delete", http.MethodDelete, unknown, nil, http.StatusNotFound},
	}
	for _, tc := range cases {
		rec := s.do(s.admin, tc.method, tc.path, tc.body)
		s.Equal(tc.want, rec.Code, "%s: %s", tc.name, rec.Body.String())
	}
}

// TestDeleteKeepsSSPs checks the instance foreign keys: deleting an SSP nulls its
// instance's ssp_id, and deleting the template drops its instances but keeps its SSPs.
func (s *SSPTemplateApiIntegrationSuite) TestDeleteKeepsSSPs() {
	templateID := uuid.MustParse(s.create(templateBody("Applications", "_app"))["id"].(string))
	kept, deleted := uuid.New(), uuid.New()
	for i, sspID := range []uuid.UUID{kept, deleted} {
		id := sspID
		s.Require().NoError(s.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &id}}).Error)
		s.Require().NoError(s.DB.Create(&relational.SSPTemplateInstance{
			TemplateID: templateID,
			KeyHash:    []string{"a", "b"}[i],
			KeyValues:  datatypes.JSONMap{"_app": []string{"a", "b"}[i]},
			SSPID:      &id,
		}).Error)
	}

	s.Require().NoError(s.DB.Delete(&relational.SystemSecurityPlan{}, "id = ?", deleted).Error)
	var instance relational.SSPTemplateInstance
	s.Require().NoError(s.DB.Where("key_hash = ?", "b").First(&instance).Error)
	s.Nil(instance.SSPID, "deleting the SSP keeps the instance, so discovery does not recreate it")
	got := s.decode(s.do(s.admin, http.MethodGet, "/"+templateID.String(), nil), http.StatusOK)["data"].(map[string]any)
	s.Equal(float64(1), got["ssp-count"], "only SSPs that still exist count")

	s.Require().Equal(http.StatusNoContent, s.do(s.admin, http.MethodDelete, "/"+templateID.String(), nil).Code)
	var instances, ssps int64
	s.Require().NoError(s.DB.Model(&relational.SSPTemplateInstance{}).Count(&instances).Error)
	s.Require().NoError(s.DB.Model(&relational.SystemSecurityPlan{}).Where("id = ?", kept).Count(&ssps).Error)
	s.Zero(instances)
	s.Equal(int64(1), ssps)
}

func (s *SSPTemplateApiIntegrationSuite) evidence(pairs ...string) {
	id, stream := uuid.New(), uuid.New()
	labels := []relational.Labels{}
	for i := 0; i+1 < len(pairs); i += 2 {
		labels = append(labels, relational.Labels{Name: pairs[i], Value: pairs[i+1]})
	}
	s.Require().NoError(s.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &id}, UUID: stream, Title: "e",
		Start: time.Now().Add(-time.Minute), End: time.Now(), Labels: labels,
	}).Error)
}

func (s *SSPTemplateApiIntegrationSuite) TestPreview() {
	s.evidence("_app", "Payments", "repo", "A")
	s.evidence("_app", "Payments", "repo", "b")
	s.evidence("repo", "c")
	body := templateBody("Applications", "_app")
	body["scope-labels"] = [][]string{{"repo"}}
	saved := s.create(body)

	// A saved template's instance marks its group as existing.
	sspID := uuid.New()
	s.Require().NoError(s.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	_, keyHash, err := sspscope.Normalize([]relational.ScopeLabel{{Key: "_app", Value: "payments"}})
	s.Require().NoError(err)
	s.Require().NoError(s.DB.Create(&relational.SSPTemplateInstance{
		TemplateID: uuid.MustParse(saved["id"].(string)), KeyHash: keyHash,
		KeyValues: datatypes.JSONMap{"_app": "payments"}, SSPID: &sspID,
	}).Error)
	s.Require().NoError(s.DB.Create(&relational.SSPScopeException{
		SSPID: sspID, Labels: []relational.ScopeLabel{{Key: "repo", Value: "b"}}, MatchHash: sspscope.MatchHash([]relational.ScopeLabel{{Key: "repo", Value: "b"}}),
	}).Error)

	for _, tc := range []struct {
		name   string
		id     any
		exists bool
		learn  []any
	}{
		{"unsaved", nil, false, []any{
			[]any{map[string]any{"key": "_app", "value": "Payments"}},
			[]any{map[string]any{"key": "repo", "value": "A"}},
			[]any{map[string]any{"key": "repo", "value": "b"}},
		}},
		{"saved", saved["id"], true, []any{
			[]any{map[string]any{"key": "_app", "value": "Payments"}},
			[]any{map[string]any{"key": "repo", "value": "A"}},
		}},
	} {
		body["id"] = tc.id
		plan := s.decode(s.do(s.admin, http.MethodPost, "/preview", body), http.StatusOK)["data"].(map[string]any)
		s.Equal(float64(1), plan["missing-keys"], tc.name)
		ssps := plan["ssps"].([]any)
		s.Require().Len(ssps, 1, tc.name)
		ssp := ssps[0].(map[string]any)
		s.Equal(map[string]any{"_app": "Payments"}, ssp["key-values"], tc.name)
		s.Equal("SSP for Payments", ssp["title"], tc.name)
		s.Equal(float64(2), ssp["streams"], tc.name)
		s.Equal(tc.exists, ssp["exists"], tc.name)
		s.Equal(tc.learn, ssp["learn"], tc.name)
	}

	var entries int64
	s.Require().NoError(s.DB.Model(&relational.SSPScopeEntry{}).Count(&entries).Error)
	s.Zero(entries, "preview writes nothing")

	body["id"] = uuid.NewString()
	s.Equal(http.StatusNotFound, s.do(s.admin, http.MethodPost, "/preview", body).Code)
	s.Equal(http.StatusBadRequest, s.do(s.admin, http.MethodPost, "/preview", templateBody("No keys")).Code)
	s.Equal(http.StatusForbidden, s.do(s.contributor, http.MethodPost, "/preview", templateBody("Apps", "_app")).Code)
}
