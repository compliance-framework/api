package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/labstack/echo/v4"
)

// fakePDP returns a programmed decision/error and records the last subject it saw.
type fakePDP struct {
	decision authz.Decision
	err      error
	lastSub  authz.Subject
	lastAct  string
	lastRes  authz.Resource
}

func (f *fakePDP) Evaluate(_ context.Context, s authz.Subject, action string, r authz.Resource, _ map[string]any) (authz.Decision, error) {
	f.lastSub = s
	f.lastAct = action
	f.lastRes = r
	return f.decision, f.err
}

func (f *fakePDP) Evaluations(_ context.Context, reqs []authz.EvalRequest) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(reqs))
	for i := range reqs {
		out[i] = f.decision
	}
	return out, f.err
}

func runAuthorize(t *testing.T, pdp authz.PDP, failMode authz.FailMode, setup func(c echo.Context)) (int, bool) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/evidence", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if setup != nil {
		setup(c)
	}

	called := false
	next := func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	}

	pep := NewPEP(pdp, failMode, nil)
	h := pep.Authorize(authz.ResourceEvidence, authz.ActionCreate)(next)
	if err := h(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec.Code, called
}

func TestPEPAllow(t *testing.T) {
	code, called := runAuthorize(t, &fakePDP{decision: authz.Decision{Allow: true}}, authz.FailClosed, nil)
	if !called {
		t.Error("expected next to be called on allow")
	}
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestPEPDeny(t *testing.T) {
	code, called := runAuthorize(t, &fakePDP{decision: authz.Decision{Allow: false, Reason: "nope"}}, authz.FailClosed, nil)
	if called {
		t.Error("expected next NOT to be called on deny")
	}
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestPEPUnavailableFailClosed(t *testing.T) {
	code, called := runAuthorize(t, &fakePDP{err: authz.ErrUnavailable}, authz.FailClosed, nil)
	if called {
		t.Error("expected next NOT to be called when PDP unavailable and fail-closed")
	}
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestPEPUnavailableFailOpen(t *testing.T) {
	code, called := runAuthorize(t, &fakePDP{err: authz.ErrUnavailable}, authz.FailOpen, nil)
	if !called {
		t.Error("expected next to be called when PDP unavailable and fail-open")
	}
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestPEPInternalErrorIs500(t *testing.T) {
	code, called := runAuthorize(t, &fakePDP{err: context.DeadlineExceeded}, authz.FailClosed, nil)
	if called {
		t.Error("expected next NOT to be called on internal error")
	}
	if code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (a non-ErrUnavailable error must not be governed by fail mode)", code, http.StatusInternalServerError)
	}
}

func TestPEPBuildsSubjectFromContext(t *testing.T) {
	t.Run("user", func(t *testing.T) {
		pdp := &fakePDP{decision: authz.Decision{Allow: true}}
		runAuthorize(t, pdp, authz.FailClosed, func(c echo.Context) {
			c.Set("user", &authn.UserClaims{GivenName: "Al", FamilyName: "Ice"})
		})
		if pdp.lastSub.Type != "user" {
			t.Errorf("subject type = %q, want user", pdp.lastSub.Type)
		}
	})

	t.Run("agent", func(t *testing.T) {
		pdp := &fakePDP{decision: authz.Decision{Allow: true}}
		runAuthorize(t, pdp, authz.FailClosed, func(c echo.Context) {
			c.Set("agent_claims", &authn.AgentClaims{AgentID: "agent-7"})
		})
		if pdp.lastSub.Type != "agent" {
			t.Errorf("subject type = %q, want agent", pdp.lastSub.Type)
		}
		if pdp.lastSub.Props["agent_id"] != "agent-7" {
			t.Errorf("agent_id prop = %v, want agent-7", pdp.lastSub.Props["agent_id"])
		}
	})

	t.Run("anonymous", func(t *testing.T) {
		pdp := &fakePDP{decision: authz.Decision{Allow: true}}
		runAuthorize(t, pdp, authz.FailClosed, nil)
		if pdp.lastSub.Type != "anonymous" {
			t.Errorf("subject type = %q, want anonymous", pdp.lastSub.Type)
		}
	})
}
