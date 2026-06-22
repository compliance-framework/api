package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestCamelToSnake(t *testing.T) {
	cases := map[string]string{
		"sspId":    "ssp_id",
		"parentId": "parent_id",
		"id":       "id",
		"ssp_id":   "ssp_id",
		"":         "",
	}
	for in, want := range cases {
		if got := camelToSnake(in); got != want {
			t.Errorf("camelToSnake(%q) = %q, want %q", in, got, want)
		}
	}
}

// runScopedAuthorize drives the PEP with options and a configured set of path params,
// returning the fake PDP so the test can inspect the resource it built.
func runScopedAuthorize(t *testing.T, paramNames, paramValues []string, opts ...AuthorizeOption) *fakePDP {
	t.Helper()
	pdp := &fakePDP{decision: authz.Decision{Allow: true}}
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", http.NoBody), httptest.NewRecorder())
	c.SetParamNames(paramNames...)
	c.SetParamValues(paramValues...)

	pep := NewPEP(pdp, authz.FailClosed, nil)
	h := pep.Authorize("risk", authz.ActionRead, opts...)(func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	if err := h(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return pdp
}

func TestAuthorizeScopeParamBindsResourceProp(t *testing.T) {
	pdp := runScopedAuthorize(t, []string{"sspId", "id"}, []string{"ssp-1", "r-9"}, ScopeParam("sspId"))
	if pdp.lastRes.ID != "r-9" {
		t.Errorf("resource ID = %q, want r-9 (default id param)", pdp.lastRes.ID)
	}
	if pdp.lastRes.Props["ssp_id"] != "ssp-1" {
		t.Errorf("ssp_id prop = %v, want ssp-1", pdp.lastRes.Props["ssp_id"])
	}
}

func TestAuthorizeResourceIDParamOverride(t *testing.T) {
	pdp := runScopedAuthorize(t, []string{"sspId"}, []string{"ssp-1"}, ResourceIDParam("sspId"))
	if pdp.lastRes.ID != "ssp-1" {
		t.Errorf("resource ID = %q, want ssp-1 (ResourceIDParam override)", pdp.lastRes.ID)
	}
}

func TestAuthorizeScopeParamAbsentLeavesPropUnset(t *testing.T) {
	// The scope param is declared but the route doesn't carry it: no empty prop is injected.
	pdp := runScopedAuthorize(t, nil, nil, ScopeParam("sspId"))
	if _, ok := pdp.lastRes.Props["ssp_id"]; ok {
		t.Errorf("ssp_id prop should be absent when the param is empty, got %v", pdp.lastRes.Props["ssp_id"])
	}
}

func TestSubjectFromContextSurfacesUserUUID(t *testing.T) {
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", http.NoBody), httptest.NewRecorder())
	c.Set("user", &authn.UserClaims{UserUUID: "uuid-123"})
	if got := SubjectFromContext(c).Props["user_uuid"]; got != "uuid-123" {
		t.Errorf("user_uuid prop = %v, want uuid-123", got)
	}

	c2 := e.NewContext(httptest.NewRequest(http.MethodGet, "/", http.NoBody), httptest.NewRecorder())
	c2.Set("user", &authn.UserClaims{})
	if _, ok := SubjectFromContext(c2).Props["user_uuid"]; ok {
		t.Error("user_uuid prop should be absent when the claim is empty")
	}
}

func runAuditedAuthorize(t *testing.T, pdp authz.PDP, failMode authz.FailMode) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(zap.InfoLevel)
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/evidence", http.NoBody), httptest.NewRecorder())
	pep := NewPEP(pdp, failMode, zap.New(core).Sugar())
	h := pep.Authorize(authz.ResourceEvidence, authz.ActionCreate)(func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	if err := h(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return logs
}

func TestAuthorizeEmitsAuditOnEveryDecision(t *testing.T) {
	t.Run("deny", func(t *testing.T) {
		logs := runAuditedAuthorize(t, &fakePDP{decision: authz.Decision{Allow: false, Reason: "nope"}}, authz.FailClosed)
		entries := logs.FilterMessage("authz decision").All()
		if len(entries) != 1 {
			t.Fatalf("expected 1 audit record, got %d", len(entries))
		}
		fields := entries[0].ContextMap()
		if fields["decision"] != "deny" {
			t.Errorf("decision = %v, want deny", fields["decision"])
		}
		if fields["action"] != authz.ActionCreate {
			t.Errorf("action = %v, want %s", fields["action"], authz.ActionCreate)
		}
		if fields["resource"] != authz.ResourceEvidence {
			t.Errorf("resource = %v, want %s", fields["resource"], authz.ResourceEvidence)
		}
		if _, ok := fields["latencyMs"]; !ok {
			t.Error("audit record missing latencyMs")
		}
	})

	t.Run("allow", func(t *testing.T) {
		logs := runAuditedAuthorize(t, &fakePDP{decision: authz.Decision{Allow: true}}, authz.FailClosed)
		if got := logs.FilterMessage("authz decision").Len(); got != 1 {
			t.Fatalf("expected 1 audit record on allow, got %d", got)
		}
	})

	t.Run("unavailable still audits", func(t *testing.T) {
		logs := runAuditedAuthorize(t, &fakePDP{err: authz.ErrUnavailable}, authz.FailClosed)
		entries := logs.FilterMessage("authz decision").All()
		if len(entries) != 1 {
			t.Fatalf("expected 1 audit record when PDP unavailable, got %d", len(entries))
		}
		if entries[0].ContextMap()["decision"] != "deny" {
			t.Errorf("fail-closed unavailable should audit as deny")
		}
	})
}
