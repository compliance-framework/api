//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func TestFilterBadges(t *testing.T) {
	suite.Run(t, new(FilterBadgeIntegrationSuite))
}

type FilterBadgeIntegrationSuite struct {
	tests.IntegrationTestSuite
	logger *zap.SugaredLogger

	// builtin is the default server: builtin PDP, admin is the password super admin.
	builtin *api.Server
	admin   string

	// cedar uses the Cedar PDP with admin and contributor role users.
	cedar            *api.Server
	cedarAdmin       string
	cedarContributor string
}

func (s *FilterBadgeIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
	s.logger = zap.NewNop().Sugar()

	s.builtin = s.newServer(nil, false)
	token, err := s.GetAuthToken()
	s.Require().NoError(err)
	s.admin = *token

	s.cedarAdmin = s.roleToken("cedar-admin@example.com", "admin")
	s.cedarContributor = s.roleToken("contributor@example.com", "contributor")
	pdp, err := authz.Open(authz.Options{Driver: authz.DriverCedar}, authz.Deps{DB: s.DB, Config: s.Config, Logger: s.logger})
	s.Require().NoError(err)
	s.cedar = s.newServer(middleware.NewPEP(pdp, authz.FailClosed, s.logger), false)
}

func (s *FilterBadgeIntegrationSuite) newServer(pep *middleware.PEP, strict bool) *api.Server {
	cfg := *s.Config
	cfg.StrictDisablePublicAgentEndpoints = strict
	server := api.NewServer(context.Background(), s.logger, &cfg, api.NewMetricsHandler(context.Background(), s.logger))
	RegisterHandlers(server, s.logger, s.DB, &cfg, &APIServices{
		EvidenceService: evidencesvc.NewEvidenceService(s.DB, s.logger, &cfg, nil),
		PEP:             pep,
	})
	return server
}

func (s *FilterBadgeIntegrationSuite) roleToken(email, role string) string {
	user := relational.User{Email: email, FirstName: "Badge", LastName: "Tester", AuthMethod: "sso"}
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

func (s *FilterBadgeIntegrationSuite) do(srv *api.Server, method, path, token string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		s.Require().NoError(err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.E().ServeHTTP(rec, req)
	return rec
}

func (s *FilterBadgeIntegrationSuite) decode(rec *httptest.ResponseRecorder) relational.Filter {
	var out GenericDataResponse[relational.Filter]
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return out.Data
}

func providerFilter(value string) labelfilter.Filter {
	return labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "provider", Operator: "=", Value: value}}}
}

func filterBody(name, provider string, extra map[string]any) map[string]any {
	body := map[string]any{"name": name, "filter": providerFilter(provider)}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// create posts a filter as the builtin admin and returns it.
func (s *FilterBadgeIntegrationSuite) create(name, provider string, badge any) relational.Filter {
	extra := map[string]any{}
	if badge != nil {
		extra["badge"] = badge
	}
	rec := s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody(name, provider, extra))
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	return s.decode(rec)
}

func (s *FilterBadgeIntegrationSuite) stored(id uuid.UUID) relational.Filter {
	var filter relational.Filter
	s.Require().NoError(s.DB.Preload("Controls").First(&filter, "id = ?", id).Error)
	return filter
}

func published(slug string) map[string]any {
	return map[string]any{"enabled": true, "slug": slug}
}

func (s *FilterBadgeIntegrationSuite) evidence(stream uuid.UUID, provider, state string, age time.Duration) {
	end := time.Now().Add(-age)
	s.Require().NoError(s.DB.Create(&relational.Evidence{
		UUID:   stream,
		Title:  "evidence-title-" + provider,
		Start:  end.Add(-time.Minute),
		End:    end,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: state}),
		Labels: []relational.Labels{{Name: "provider", Value: provider}},
	}).Error)
}

func (s *FilterBadgeIntegrationSuite) public(srv *api.Server, file string) *httptest.ResponseRecorder {
	return s.do(srv, http.MethodGet, "/api/public/badges/"+file, "", nil)
}

func (s *FilterBadgeIntegrationSuite) assertBadge(rec *httptest.ResponseRecorder, label, state, cacheControl string) {
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal("image/svg+xml; charset=utf-8", rec.Header().Get(echo.HeaderContentType))
	s.Equal(cacheControl, rec.Header().Get("Cache-Control"))
	s.Equal("nosniff", rec.Header().Get("X-Content-Type-Options"))
	s.Equal("default-src 'none'; style-src 'unsafe-inline'; sandbox", rec.Header().Get("Content-Security-Policy"))
	s.Contains(rec.Body.String(), "<title>"+label+": "+state+"</title>")
}

func (s *FilterBadgeIntegrationSuite) assertPublic(srv *api.Server, slug, state string) {
	s.assertBadge(s.public(srv, slug+".svg"), "compliance", state, "public, no-cache, max-age=0, must-revalidate")
}

// assertPublicNotFound checks the single generic, uncacheable public 404.
func (s *FilterBadgeIntegrationSuite) assertPublicNotFound(file string) {
	rec := s.public(s.builtin, file)
	s.Equal(http.StatusNotFound, rec.Code, file)
	s.Equal("no-store", rec.Header().Get("Cache-Control"), file)
	s.JSONEq(`{"errors":{"body":"resource not found"}}`, rec.Body.String(), file)
}

// waitForLockWaiter blocks until some session is waiting on a lock.
func (s *FilterBadgeIntegrationSuite) waitForLockWaiter() {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int64
		s.Require().NoError(s.DB.Raw(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'`).Scan(&waiting).Error)
		if waiting > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.FailNow("no request blocked on the lock")
}

func (s *FilterBadgeIntegrationSuite) TestExistingFiltersMigrateUnpublished() {
	s.Require().NoError(s.DB.Exec(`ALTER TABLE filters DROP COLUMN badge_enabled, DROP COLUMN badge_label, DROP COLUMN badge_slug`).Error)
	id := uuid.New()
	s.Require().NoError(s.DB.Exec(`INSERT INTO filters (id, name, filter) VALUES (?, 'legacy', '{}')`, id).Error)

	s.Require().NoError(s.Migrator.Up())

	s.Equal(relational.DefaultFilterBadge(), s.stored(id).Badge)
	s.Error(s.DB.Exec(`UPDATE filters SET badge_enabled = true WHERE id = ?`, id).Error, "an enabled badge needs a slug")
	s.Error(s.DB.Exec(`UPDATE filters SET badge_slug = '' WHERE id = ?`, id).Error, "an absent slug is NULL")
	s.Require().NoError(s.DB.Exec(`UPDATE filters SET badge_slug = 'taken' WHERE id = ?`, id).Error)
	s.Error(s.DB.Exec(`INSERT INTO filters (id, name, filter, badge_slug) VALUES (?, 'dup', '{}', 'taken')`, uuid.New()).Error, "slugs are unique")
}

func (s *FilterBadgeIntegrationSuite) TestDefaultsAndOlderClients() {
	created := s.create("plain", "aws", nil)
	s.Equal(relational.DefaultFilterBadge(), created.Badge)
	s.Equal(relational.DefaultFilterBadge(), s.stored(*created.ID).Badge)

	pub := s.create("pub", "aws", map[string]any{"enabled": true, "slug": "pub", "label": " payments "})
	s.Equal(relational.FilterBadge{Enabled: true, Label: "payments", Slug: &[]string{"pub"}[0]}, pub.Badge)

	// A PUT without badge keeps the settings; so does an identical round trip, which a
	// contributor without filter:publish may send while leaving the selection alone.
	path := "/api/filters/" + pub.ID.String()
	rec := s.do(s.cedar, http.MethodPut, path, s.cedarContributor, filterBody("renamed", "aws", nil))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(pub.Badge, s.decode(rec).Badge)
	rec = s.do(s.cedar, http.MethodPut, path, s.cedarContributor, filterBody("renamed", "aws", map[string]any{"badge": pub.Badge}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(pub.Badge, s.stored(*pub.ID).Badge)
	s.assertBadge(s.public(s.builtin, "pub.svg"), "payments", "no evidence", "public, no-cache, max-age=0, must-revalidate")

	// badge: null resets everything.
	rec = s.do(s.builtin, http.MethodPut, path, s.admin, filterBody("renamed", "aws", map[string]any{"badge": nil}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.Equal(relational.DefaultFilterBadge(), s.stored(*pub.ID).Badge)
	s.assertPublicNotFound("pub.svg")
}

func (s *FilterBadgeIntegrationSuite) TestInvalidSettingsRejected() {
	for _, badge := range []any{
		map[string]any{"enabled": true},
		map[string]any{"enabled": true, "slug": nil},
		map[string]any{"slug": ""},
		map[string]any{"slug": "Upper"},
		map[string]any{"slug": "a_b"},
		map[string]any{"label": " "},
		map[string]any{"label": "bell\u0007"},
		map[string]any{"label": strings.Repeat("x", 65)},
		"not-an-object",
	} {
		rec := s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody("bad", "aws", map[string]any{"badge": badge}))
		s.Equal(http.StatusBadRequest, rec.Code, "%v: %s", badge, rec.Body.String())
	}
	var count int64
	s.Require().NoError(s.DB.Model(&relational.Filter{}).Count(&count).Error)
	s.Zero(count)
}

func (s *FilterBadgeIntegrationSuite) TestSlugReservationAndRollback() {
	s.Require().NoError(s.DB.Create(&relational.Catalog{
		Metadata: relational.Metadata{Title: "Catalog"},
		Controls: []relational.Control{{ID: "AC-1", Title: "Access Control 1"}},
	}).Error)

	a := s.create("a", "aws", published("shared"))
	rec := s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody("b", "aws", map[string]any{"badge": published("shared")}))
	s.Equal(http.StatusConflict, rec.Code, rec.Body.String())

	b := s.create("b", "aws", nil)
	bPath := "/api/filters/" + b.ID.String()
	rec = s.do(s.builtin, http.MethodPut, bPath, s.admin, filterBody("b", "aws", map[string]any{"controls": []string{"AC-1"}}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	// A conflicting update changes nothing, associations included.
	rec = s.do(s.builtin, http.MethodPut, bPath, s.admin, filterBody("b-renamed", "gcp", map[string]any{
		"controls": []string{}, "badge": map[string]any{"slug": "shared"},
	}))
	s.Equal(http.StatusConflict, rec.Code, rec.Body.String())
	kept := s.stored(*b.ID)
	s.Equal("b", kept.Name)
	s.Equal(providerFilter("aws"), kept.Filter.Data())
	s.Len(kept.Controls, 1)
	s.Nil(kept.Badge.Slug)

	// A disabled filter keeps its slug reserved.
	aPath := "/api/filters/" + a.ID.String()
	rec = s.do(s.builtin, http.MethodPut, aPath, s.admin, filterBody("a", "aws", map[string]any{"badge": map[string]any{"enabled": false}}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.assertPublicNotFound("shared.svg")
	rec = s.do(s.builtin, http.MethodPut, bPath, s.admin, filterBody("b", "aws", map[string]any{"badge": published("shared")}))
	s.Equal(http.StatusConflict, rec.Code, rec.Body.String())

	// Re-enabling by the same filter works, renaming frees the old slug for another.
	rec = s.do(s.builtin, http.MethodPut, aPath, s.admin, filterBody("a", "aws", map[string]any{"badge": published("renamed")}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.assertPublicNotFound("shared.svg")
	s.assertPublic(s.builtin, "renamed", "no evidence")
	rec = s.do(s.builtin, http.MethodPut, bPath, s.admin, filterBody("b", "aws", map[string]any{"badge": published("shared")}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.assertPublic(s.builtin, "shared", "no evidence")

	// Clearing a slug, or deleting its filter, frees it too.
	rec = s.do(s.builtin, http.MethodPut, bPath, s.admin, filterBody("b", "aws", map[string]any{"badge": map[string]any{"slug": nil}}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.assertPublicNotFound("shared.svg")
	s.Require().Equal(http.StatusNoContent, s.do(s.builtin, http.MethodDelete, aPath, s.admin, nil).Code)
	s.assertPublicNotFound("renamed.svg")
	reclaimed := s.create("c", "aws", published("renamed"))
	s.Equal("renamed", *reclaimed.Badge.Slug)
	s.assertPublic(s.builtin, "renamed", "no evidence")
}

// A claim racing another transaction past the pre-check is decided by the unique index,
// and still answered with 409.
func (s *FilterBadgeIntegrationSuite) TestConcurrentSlugClaim() {
	slug := "race"
	tx := s.DB.Begin()
	defer tx.Rollback()
	s.Require().NoError(tx.Create(&relational.Filter{
		Name:   "holder",
		Filter: datatypes.NewJSONType(providerFilter("aws")),
		Badge:  relational.FilterBadge{Label: "compliance", Slug: &slug},
	}).Error)

	done := make(chan *httptest.ResponseRecorder)
	go func() {
		done <- s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody("claimer", "aws", map[string]any{"badge": published(slug)}))
	}()
	s.waitForLockWaiter()
	s.Require().NoError(tx.Commit().Error)

	rec := <-done
	s.Equal(http.StatusConflict, rec.Code, rec.Body.String())
	s.NotContains(rec.Body.String(), relational.FilterBadgeSlugIndex, "driver errors stay server-side")
	var count int64
	s.Require().NoError(s.DB.Model(&relational.Filter{}).Count(&count).Error)
	s.Equal(int64(1), count)
}

func (s *FilterBadgeIntegrationSuite) TestParallelSlugClaims() {
	const n = 4
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			codes <- s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody("p", "aws", map[string]any{"badge": published("parallel")})).Code
		})
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for code := range codes {
		got[code]++
	}
	s.Equal(map[int]int{http.StatusCreated: 1, http.StatusConflict: n - 1}, got)
}

func (s *FilterBadgeIntegrationSuite) TestPublishAuthorization() {
	s.Require().NoError(s.DB.Create(&relational.Catalog{
		Metadata: relational.Metadata{Title: "Catalog"},
		Controls: []relational.Control{{ID: "AC-1", Title: "Access Control 1"}},
	}).Error)
	sspID := uuid.New()
	s.Require().NoError(s.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)

	// Contributors may manage filters but not publish them.
	rec := s.do(s.cedar, http.MethodPost, "/api/filters", s.cedarContributor, filterBody("c", "aws", map[string]any{"badge": published("contrib")}))
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	rec = s.do(s.cedar, http.MethodPost, "/api/filters", s.cedarContributor, filterBody("c", "aws", map[string]any{"badge": map[string]any{"label": "x"}}))
	s.Equal(http.StatusForbidden, rec.Code, "any badge change needs publish: %s", rec.Body.String())
	rec = s.do(s.cedar, http.MethodPost, "/api/filters", s.cedarContributor, filterBody("c", "aws", map[string]any{"controls": []string{"AC-1"}}))
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	unpublished := s.decode(rec)
	path := "/api/filters/" + unpublished.ID.String()

	rec = s.do(s.cedar, http.MethodPut, path, s.cedarContributor, filterBody("c", "gcp", nil))
	s.Require().Equal(http.StatusOK, rec.Code, "an unpublished filter's selection is not gated: %s", rec.Body.String())
	rec = s.do(s.cedar, http.MethodPut, path, s.cedarContributor, filterBody("c", "gcp", map[string]any{"badge": published("contrib")}))
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	s.Nil(s.stored(*unpublished.ID).Badge.Slug)

	rec = s.do(s.cedar, http.MethodPut, path, s.cedarAdmin, filterBody("c", "gcp", map[string]any{"badge": published("contrib"), "controls": []string{"AC-1"}}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	// Once published, changing the predicate or SSP binding needs publish, and a denial
	// leaves every part of the update unapplied.
	rec = s.do(s.cedar, http.MethodPut, path, s.cedarContributor, filterBody("changed", "azure", map[string]any{"controls": []string{}}))
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	rec = s.do(s.cedar, http.MethodPut, path, s.cedarContributor, filterBody("changed", "gcp", map[string]any{"sspId": sspID}))
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	rec = s.do(s.cedar, http.MethodPut, path, s.cedarContributor, filterBody("c", "gcp", map[string]any{"badge": map[string]any{"enabled": false}}))
	s.Equal(http.StatusForbidden, rec.Code, "unpublishing is a badge change: %s", rec.Body.String())
	kept := s.stored(*unpublished.ID)
	s.Equal("c", kept.Name)
	s.Equal(providerFilter("gcp"), kept.Filter.Data())
	s.Nil(kept.SSPID)
	s.Len(kept.Controls, 1)
	s.True(kept.Badge.Enabled)

	rec = s.do(s.cedar, http.MethodPut, path, s.cedarAdmin, filterBody("c", "azure", nil))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	// Delete keeps its own permission and revokes the badge.
	s.assertPublic(s.builtin, "contrib", "no evidence")
	s.Require().Equal(http.StatusNoContent, s.do(s.cedar, http.MethodDelete, path, s.cedarContributor, nil).Code)
	s.assertPublicNotFound("contrib.svg")
}

// badgeStubPDP allows everything except the listed "resource:action" keys.
type badgeStubPDP struct {
	deny, unavailable, fail map[string]bool
}

func (p badgeStubPDP) Evaluate(_ context.Context, _ authz.Subject, action string, r authz.Resource, _ map[string]any) (authz.Decision, error) {
	key := r.Type + ":" + action
	switch {
	case p.unavailable[key]:
		return authz.Decision{}, authz.ErrUnavailable
	case p.fail[key]:
		return authz.Decision{}, errors.New("policy evaluation exploded")
	}
	return authz.Decision{Allow: !p.deny[key]}, nil
}

func (p badgeStubPDP) Evaluations(ctx context.Context, reqs []authz.EvalRequest) ([]authz.Decision, error) {
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

// Publication fails closed even when ordinary authorization is configured fail-open.
func (s *FilterBadgeIntegrationSuite) TestPublishFailsClosed() {
	key := authz.ResourceFilter + ":" + authz.ActionPublish
	unavailable := s.newServer(middleware.NewPEP(badgeStubPDP{unavailable: map[string]bool{key: true}}, authz.FailOpen, s.logger), false)
	failing := s.newServer(middleware.NewPEP(badgeStubPDP{fail: map[string]bool{key: true}}, authz.FailOpen, s.logger), false)

	rec := s.do(unavailable, http.MethodPost, "/api/filters", s.admin, filterBody("f", "aws", map[string]any{"badge": published("closed")}))
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	rec = s.do(failing, http.MethodPost, "/api/filters", s.admin, filterBody("f", "aws", map[string]any{"badge": published("closed")}))
	s.Equal(http.StatusInternalServerError, rec.Code, rec.Body.String())
	s.NotContains(rec.Body.String(), "exploded")

	f := s.create("f", "aws", published("closed"))
	rec = s.do(unavailable, http.MethodPut, "/api/filters/"+f.ID.String(), s.admin, filterBody("f", "gcp", nil))
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	s.Equal(providerFilter("aws"), s.stored(*f.ID).Filter.Data())

	// Without a publish decision needed, the PDP is never asked.
	rec = s.do(unavailable, http.MethodPut, "/api/filters/"+f.ID.String(), s.admin, filterBody("renamed", "aws", nil))
	s.Equal(http.StatusOK, rec.Code, rec.Body.String())
}

// An update authorized while the badge was disabled must not commit over a concurrent
// publication: the row lock makes it re-decide against the published state.
func (s *FilterBadgeIntegrationSuite) TestConcurrentUpdateAndEnable() {
	f := s.create("f", "aws", map[string]any{"slug": "racing"})
	tx := s.DB.Begin()
	defer tx.Rollback()
	s.Require().NoError(tx.Exec(`SELECT id FROM filters WHERE id = ? FOR UPDATE`, f.ID).Error)
	s.Require().NoError(tx.Exec(`UPDATE filters SET badge_enabled = true WHERE id = ?`, f.ID).Error)

	done := make(chan *httptest.ResponseRecorder)
	go func() {
		done <- s.do(s.cedar, http.MethodPut, "/api/filters/"+f.ID.String(), s.cedarContributor, filterBody("f", "gcp", nil))
	}()
	s.waitForLockWaiter()
	s.Require().NoError(tx.Commit().Error)

	rec := <-done
	s.Equal(http.StatusForbidden, rec.Code, rec.Body.String())
	kept := s.stored(*f.ID)
	s.True(kept.Badge.Enabled)
	s.Equal(providerFilter("aws"), kept.Filter.Data())
}

func (s *FilterBadgeIntegrationSuite) TestUpdateLocksScopeBeforeFilter() {
	sspID := uuid.New()
	s.Require().NoError(s.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	_, err := sspscope.NewService(s.DB).AddEntry(sspID, []relational.ScopeLabel{{Key: "repo", Value: "a"}}, nil)
	s.Require().NoError(err)
	rec := s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody("f", "aws", map[string]any{
		"sspId": sspID, "followSspScope": true,
	}))
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	f := s.decode(rec)

	tx := s.DB.Begin()
	defer tx.Rollback()
	effective, err := sspscope.FollowScope(tx, sspID, providerFilter("aws"))
	s.Require().NoError(err)
	s.Require().NoError(tx.Exec("SET LOCAL lock_timeout = '1s'").Error)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- s.do(s.builtin, http.MethodPut, "/api/filters/"+f.ID.String(), s.admin,
			filterBody("updated", "gcp", map[string]any{"sspId": sspID}))
	}()
	s.waitForLockWaiter()
	s.Require().NoError(tx.Model(&f).Update("filter", datatypes.NewJSONType(effective)).Error,
		"the scope writer must be able to lock the filter while Update waits for the scope")
	s.Require().NoError(tx.Commit().Error)

	rec = <-done
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	kept := s.stored(*f.ID)
	s.Equal("updated", kept.Name)
	s.Require().NotNil(kept.ScopeBase)
	s.Equal(providerFilter("gcp"), kept.ScopeBase.Data())
}

// Moving a filter off an SSP waits for that SSP's scope edits, so they cannot rewrite the
// moved filter with the old scope.
func (s *FilterBadgeIntegrationSuite) TestUpdateLocksPreviousSSPScope() {
	scope := sspscope.NewService(s.DB)
	newSSP := func(repo string) uuid.UUID {
		id := uuid.New()
		s.Require().NoError(s.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &id}}).Error)
		_, err := scope.AddEntry(id, []relational.ScopeLabel{{Key: "repo", Value: repo}}, nil)
		s.Require().NoError(err)
		return id
	}
	oldSSP, nextSSP := newSSP("a"), newSSP("b")

	for name, update := range map[string]map[string]any{
		"moved":   {"sspId": nextSSP, "followSspScope": true},
		"cleared": {"followSspScope": false},
	} {
		s.Run(name, func() {
			rec := s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody("f", "aws", map[string]any{
				"sspId": oldSSP, "followSspScope": true,
			}))
			s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
			f := s.decode(rec)

			// A scope edit on the old SSP: lock it, then list its following filters.
			tx := s.DB.Begin()
			defer tx.Rollback()
			s.Require().NoError(sspscope.LockSSP(tx, oldSSP))
			var following []uuid.UUID
			s.Require().NoError(tx.Model(&relational.Filter{}).
				Where("ssp_id = ? AND scope_base IS NOT NULL", oldSSP).Pluck("id", &following).Error)
			s.Require().Contains(following, *f.ID)

			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- s.do(s.builtin, http.MethodPut, "/api/filters/"+f.ID.String(), s.admin, filterBody("updated", "gcp", update))
			}()
			s.waitForLockWaiter()
			stale := datatypes.NewJSONType(providerFilter("stale"))
			s.Require().NoError(tx.Model(&relational.Filter{}).Where("id IN ?", following).Update("filter", stale).Error)
			s.Require().NoError(tx.Commit().Error)

			rec = <-done
			s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
			s.Equal(s.decode(rec).Filter.Data(), s.stored(*f.ID).Filter.Data(), "the scope edit must not overwrite the update")
		})
	}
}

// A scope edit rewrites a following filter without filter:publish, and the published badge
// follows it.
func (s *FilterBadgeIntegrationSuite) TestScopeEditUpdatesFollowingBadge() {
	sspID := uuid.New()
	s.Require().NoError(s.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	scope := sspscope.NewService(s.DB)
	_, err := scope.AddEntry(sspID, []relational.ScopeLabel{{Key: "repo", Value: "a"}}, nil)
	s.Require().NoError(err)

	rec := s.do(s.builtin, http.MethodPost, "/api/filters", s.admin, filterBody("f", "aws", map[string]any{
		"sspId": sspID, "followSspScope": true, "badge": published("follow"),
	}))
	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	f := s.decode(rec)

	stream := uuid.New()
	s.Require().NoError(s.DB.Create(&relational.Evidence{
		UUID: stream, Title: "b", Start: time.Now().Add(-2 * time.Minute), End: time.Now().Add(-time.Minute),
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
		Labels: []relational.Labels{{Name: "provider", Value: "aws"}, {Name: "repo", Value: "b"}},
	}).Error)
	s.assertPublic(s.builtin, "follow", "no evidence")

	_, err = scope.AddEntry(sspID, []relational.ScopeLabel{{Key: "repo", Value: "b"}}, nil)
	s.Require().NoError(err)
	s.assertPublic(s.builtin, "follow", "failing")
	s.True(s.stored(*f.ID).Badge.Enabled)

	// Re-sending the same base with the unchanged scope is not a selection change.
	rec = s.do(s.cedar, http.MethodPut, "/api/filters/"+f.ID.String(), s.cedarContributor, filterBody("renamed", "aws", map[string]any{"sspId": sspID}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
}

func (s *FilterBadgeIntegrationSuite) TestPreview() {
	f := s.create("secret-name", "aws", nil)
	path := "/api/filters/" + f.ID.String() + "/badge.svg"

	rec := s.do(s.builtin, http.MethodGet, path, "", nil)
	s.Equal(http.StatusUnauthorized, rec.Code)
	s.Equal("no-store", rec.Header().Get("Cache-Control"))

	s.assertBadge(s.do(s.builtin, http.MethodGet, path, s.admin, nil), "compliance", "no evidence", "private, no-store")
	s.assertBadge(s.do(s.cedar, http.MethodGet, path, s.cedarContributor, nil), "compliance", "no evidence", "private, no-store")

	for _, denied := range []string{authz.ResourceFilter + ":read", authz.ResourceEvidence + ":read"} {
		srv := s.newServer(middleware.NewPEP(badgeStubPDP{deny: map[string]bool{denied: true}}, authz.FailClosed, s.logger), false)
		rec = s.do(srv, http.MethodGet, path, s.admin, nil)
		s.Equal(http.StatusForbidden, rec.Code, denied)
		s.Equal("no-store", rec.Header().Get("Cache-Control"), denied)
	}

	for p, want := range map[string]int{
		"/api/filters/not-a-uuid/badge.svg":                http.StatusBadRequest,
		"/api/filters/" + uuid.NewString() + "/badge.svg":  http.StatusNotFound,
		path + "?label=x":                                  http.StatusBadRequest,
		path + "?":                                         http.StatusOK,
		"/api/filters/" + f.ID.String() + "/badge.svg?x=1": http.StatusBadRequest,
	} {
		rec = s.do(s.builtin, http.MethodGet, p, s.admin, nil)
		s.Equal(want, rec.Code, p)
		if want != http.StatusOK {
			s.Equal("no-store", rec.Header().Get("Cache-Control"), p)
		}
	}

	// Preview works after publication and after disabling.
	rec = s.do(s.builtin, http.MethodPut, "/api/filters/"+f.ID.String(), s.admin, filterBody("secret-name", "aws", map[string]any{"badge": published("prev")}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	rec = s.do(s.builtin, http.MethodPut, "/api/filters/"+f.ID.String(), s.admin, filterBody("secret-name", "aws", map[string]any{"badge": map[string]any{"enabled": false}}))
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	s.assertBadge(s.do(s.builtin, http.MethodGet, path, s.admin, nil), "compliance", "no evidence", "private, no-store")
	s.assertPublicNotFound("prev.svg")

	// Filter JSON reads keep their cache behavior.
	s.Empty(s.do(s.builtin, http.MethodGet, "/api/filters/"+f.ID.String(), s.admin, nil).Header().Get("Cache-Control"))
}

func (s *FilterBadgeIntegrationSuite) TestPublicRouting() {
	s.create("f", "aws", published("payments-service"))
	for _, strict := range []bool{false, true} {
		srv := s.newServer(nil, strict)
		s.assertPublic(srv, "payments-service", "no evidence")
	}

	for _, file := range []string{
		"payments-service",
		"payments-service.SVG",
		"payments-service.svg.svg",
		"Payments-Service.svg",
		"unknown.svg",
		".svg",
		"payments-service.svg/extra",
		"",
	} {
		s.assertPublicNotFound(file)
	}
	rec := s.public(s.builtin, "payments-service.svg?label=x")
	s.Equal(http.StatusBadRequest, rec.Code)
	s.Equal("no-store", rec.Header().Get("Cache-Control"))
	rec = s.public(s.builtin, "unknown.svg?x")
	s.Equal(http.StatusBadRequest, rec.Code)

	// A token neither helps nor hurts.
	rec = s.do(s.builtin, http.MethodGet, "/api/public/badges/payments-service.svg", "not-a-valid-token", nil)
	s.Equal(http.StatusOK, rec.Code)
}

func (s *FilterBadgeIntegrationSuite) TestStatesParityAndDisclosure() {
	cases := []struct {
		slug     string
		provider string
		seed     func(provider string)
		state    string
	}{
		{"empty", "zq-none", func(string) {}, "no evidence"},
		{"passing", "zq-pass", func(p string) {
			s.evidence(uuid.New(), p, "satisfied", time.Hour)
			// The stream's latest evidence wins over its older failure.
			stream := uuid.New()
			s.evidence(stream, p, "not-satisfied", 2*time.Hour)
			s.evidence(stream, p, "satisfied", time.Minute)
		}, "passing"},
		{"failing", "zq-fail", func(p string) {
			s.evidence(uuid.New(), p, "satisfied", time.Hour)
			s.evidence(uuid.New(), p, "not-satisfied", time.Hour)
			s.evidence(uuid.New(), p, "mystery", time.Hour)
		}, "failing"},
		{"unknown", "zq-unk", func(p string) {
			s.evidence(uuid.New(), p, "satisfied", time.Hour)
			s.evidence(uuid.New(), p, "mystery", time.Hour)
		}, "unknown"},
	}
	for _, tc := range cases {
		tc.seed(tc.provider)
		f := s.create("secret-name-"+tc.slug, tc.provider, published(tc.slug))

		// The JSON compliance endpoint over the same filter agrees.
		rec := s.do(s.builtin, http.MethodGet, "/api/evidence/compliance-by-filter/"+f.ID.String(), s.admin, nil)
		s.Require().Equal(http.StatusOK, rec.Code)
		var counts GenericDataListResponse[evidencesvc.StatusCount]
		s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &counts))
		var total int64
		for _, c := range counts.Data {
			total += c.Count
			if tc.state == "passing" {
				s.Equal("satisfied", c.Status, tc.slug)
			}
		}
		s.Equal(tc.state == "no evidence", total == 0, tc.slug)

		rec = s.public(s.builtin, tc.slug+".svg")
		s.assertBadge(rec, "compliance", tc.state, "public, no-cache, max-age=0, must-revalidate")
		body := rec.Body.String()
		for _, secret := range []string{f.ID.String(), "secret-name", tc.provider, "evidence-title", "provider"} {
			s.NotContains(body, secret, tc.slug)
		}
	}
}

// One filter lookup and one grouped evidence query per render.
func (s *FilterBadgeIntegrationSuite) TestRenderQueryCount() {
	s.evidence(uuid.New(), "aws", "satisfied", time.Hour)
	s.evidence(uuid.New(), "aws", "not-satisfied", time.Hour)
	s.create("f", "aws", published("counted"))

	var queries int
	// Sub-queries embedded as arguments are compiled through the callbacks in DryRun
	// mode; only statements that reach the database count.
	count := func(tx *gorm.DB) {
		if !tx.DryRun {
			queries++
		}
	}
	s.Require().NoError(s.DB.Callback().Query().After("gorm:query").Register("badge_count_query", count))
	s.Require().NoError(s.DB.Callback().Row().After("gorm:row").Register("badge_count_row", count))
	defer func() {
		s.Require().NoError(s.DB.Callback().Query().Remove("badge_count_query"))
		s.Require().NoError(s.DB.Callback().Row().Remove("badge_count_row"))
	}()

	s.assertPublic(s.builtin, "counted", "failing")
	s.Equal(2, queries)
}

func (s *FilterBadgeIntegrationSuite) TestRenderFailureIsGeneric500() {
	s.create("f", "aws", published("broken"))
	s.Require().NoError(s.DB.Exec(`ALTER TABLE evidences RENAME TO evidences_hidden`).Error)
	defer func() {
		s.Require().NoError(s.DB.Exec(`ALTER TABLE evidences_hidden RENAME TO evidences`).Error)
	}()

	rec := s.public(s.builtin, "broken.svg")
	s.Equal(http.StatusInternalServerError, rec.Code)
	s.Equal("no-store", rec.Header().Get("Cache-Control"))
	s.JSONEq(`{"errors":{"body":"internal server error"}}`, rec.Body.String())
}

func (s *FilterBadgeIntegrationSuite) importRequest(token string, dashboards []map[string]any) *http.Request {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("files", "dashboards.json")
	s.Require().NoError(err)
	s.Require().NoError(json.NewEncoder(part).Encode(dashboards))
	s.Require().NoError(w.Close())
	req := httptest.NewRequest(http.MethodPost, "/api/filters/import", &buf)
	req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	return req
}

func (s *FilterBadgeIntegrationSuite) importFilters(srv *api.Server, token string, dashboards []map[string]any) FilterImportResponse {
	rec := httptest.NewRecorder()
	srv.E().ServeHTTP(rec, s.importRequest(token, dashboards))
	return s.decodeImport(rec)
}

func (s *FilterBadgeIntegrationSuite) decodeImport(rec *httptest.ResponseRecorder) FilterImportResponse {
	var out GenericDataResponse[FilterImportResponse]
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return out.Data
}

// Imports start unpublished, keep an overwritten filter's badge, and cannot change a
// published filter's selection without filter:publish.
func (s *FilterBadgeIntegrationSuite) TestImportKeepsBadges() {
	f := s.create("f", "aws", map[string]any{"enabled": true, "slug": "imported", "label": "kept"})
	dashboard := func(provider string) map[string]any {
		return map[string]any{"id": f.ID, "name": "imported-name", "filter": providerFilter(provider)}
	}

	freshID := uuid.New()
	out := s.importFilters(s.cedar, s.cedarContributor, []map[string]any{
		dashboard("aws"),
		{"name": "new", "filter": providerFilter("x")},
		{"id": freshID, "name": "new-with-id", "filter": providerFilter("x")},
	})
	s.Require().Equal(1, out.SuccessfulCount, out.Results)
	s.Equal(3, out.TotalDashboards)
	kept := s.stored(*f.ID)
	s.Equal("imported-name", kept.Name)
	s.Equal(f.Badge, kept.Badge)
	var fresh relational.Filter
	s.Require().NoError(s.DB.First(&fresh, "name = ?", "new").Error)
	s.Equal(relational.DefaultFilterBadge(), fresh.Badge)
	fresh = s.stored(freshID)
	s.Equal(providerFilter("x"), fresh.Filter.Data())
	s.Equal(relational.DefaultFilterBadge(), fresh.Badge)

	out = s.importFilters(s.cedar, s.cedarContributor, []map[string]any{dashboard("gcp")})
	s.Require().Equal(1, out.FailedCount, out.Results)
	s.Contains(out.Results[0].Message, "filter:publish")
	s.Equal(providerFilter("aws"), s.stored(*f.ID).Filter.Data())

	out = s.importFilters(s.cedar, s.cedarAdmin, []map[string]any{dashboard("gcp")})
	s.Require().Equal(1, out.SuccessfulCount, out.Results)
	kept = s.stored(*f.ID)
	s.Equal(providerFilter("gcp"), kept.Filter.Data())
	s.Equal(f.Badge, kept.Badge)
}

func (s *FilterBadgeIntegrationSuite) TestConcurrentImportAndCreate() {
	for _, tc := range []struct {
		name     string
		enabled  bool
		provider string
		token    string
		allow    bool
	}{
		{"published selection change denied", true, "gcp", s.cedarContributor, false},
		{"published selection unchanged", true, "aws", s.cedarContributor, true},
		{"published selection change authorized", true, "gcp", s.cedarAdmin, true},
		{"unpublished selection change", false, "gcp", s.cedarContributor, true},
	} {
		s.Run(tc.name, func() {
			id := uuid.New()
			slug := "import-" + id.String()
			f := relational.Filter{
				UUIDModel: relational.UUIDModel{ID: &id},
				Name:      "concurrent",
				Filter:    datatypes.NewJSONType(providerFilter("aws")),
				Badge:     relational.FilterBadge{Enabled: tc.enabled, Label: "kept", Slug: &slug},
			}
			tx := s.DB.Begin()
			defer tx.Rollback()
			s.Require().NoError(tx.Create(&f).Error)

			// The lookup cannot see the uncommitted row; the insert must wait for it.
			req := s.importRequest(tc.token, []map[string]any{
				{"id": id, "name": "imported-name", "filter": providerFilter(tc.provider)},
			})
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				rec := httptest.NewRecorder()
				s.cedar.E().ServeHTTP(rec, req)
				done <- rec
			}()
			s.waitForLockWaiter()
			s.Require().NoError(tx.Commit().Error)

			out := s.decodeImport(<-done)
			wantName, wantProvider := "imported-name", tc.provider
			if tc.allow {
				s.Require().Equal(1, out.SuccessfulCount, out.Results)
			} else {
				s.Require().Equal(1, out.FailedCount, out.Results)
				s.Require().Len(out.Results, 1)
				s.Contains(out.Results[0].Message, "filter:publish")
				wantName, wantProvider = "concurrent", "aws"
			}
			kept := s.stored(id)
			s.Equal(wantName, kept.Name)
			s.Equal(providerFilter(wantProvider), kept.Filter.Data())
			s.Equal(f.Badge, kept.Badge)
		})
	}
}
