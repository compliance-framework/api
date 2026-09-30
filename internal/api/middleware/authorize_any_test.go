package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authz"
	"github.com/labstack/echo/v4"
)

// actionPDP allows exactly the configured actions and records the batch it was asked.
type actionPDP struct {
	allowed map[string]bool
	err     error
	calls   int
	lastReq []authz.EvalRequest
}

func (p *actionPDP) Evaluate(_ context.Context, _ authz.Subject, action string, _ authz.Resource, _ map[string]any) (authz.Decision, error) {
	return authz.Decision{Allow: p.allowed[action]}, p.err
}

func (p *actionPDP) Evaluations(_ context.Context, reqs []authz.EvalRequest) ([]authz.Decision, error) {
	p.calls++
	p.lastReq = reqs
	if p.err != nil {
		return nil, p.err
	}
	out := make([]authz.Decision, len(reqs))
	for i, r := range reqs {
		out[i] = authz.Decision{Allow: p.allowed[r.Action]}
	}
	return out, nil
}

func runAuthorizeAny(t *testing.T, pdp authz.PDP, failMode authz.FailMode) (int, bool, map[string]bool) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut, "/admin/agents/a1/config", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("a1")

	called := false
	var allowed map[string]bool
	next := func(c echo.Context) error {
		called = true
		allowed = AllowedActions(c)
		return c.NoContent(http.StatusOK)
	}
	guard := NewPEP(pdp, failMode, nil).For(authz.ResourceAgent)
	h := guard.Any(authz.ActionConfigure, authz.ActionConfigurePolicy)(next)
	if err := h(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec.Code, called, allowed
}

func TestAuthorizeAnyAllowsWhenOneActionIsAllowed(t *testing.T) {
	pdp := &actionPDP{allowed: map[string]bool{authz.ActionConfigurePolicy: true}}
	code, called, allowed := runAuthorizeAny(t, pdp, authz.FailClosed)
	if !called || code != http.StatusOK {
		t.Fatalf("code=%d called=%v, want 200 and next called", code, called)
	}
	if pdp.calls != 1 || len(pdp.lastReq) != 2 {
		t.Errorf("want one Evaluations batch of 2, got calls=%d batch=%d", pdp.calls, len(pdp.lastReq))
	}
	if pdp.lastReq[0].Resource.ID != "a1" || pdp.lastReq[0].Resource.Type != authz.ResourceAgent {
		t.Errorf("resource = %+v, want agent a1", pdp.lastReq[0].Resource)
	}
	if allowed[authz.ActionConfigure] || !allowed[authz.ActionConfigurePolicy] {
		t.Errorf("AllowedActions = %v, want only configure-policy", allowed)
	}
}

func TestAuthorizeAnyAllowsAll(t *testing.T) {
	pdp := &actionPDP{allowed: map[string]bool{authz.ActionConfigure: true, authz.ActionConfigurePolicy: true}}
	_, called, allowed := runAuthorizeAny(t, pdp, authz.FailClosed)
	if !called || !allowed[authz.ActionConfigure] || !allowed[authz.ActionConfigurePolicy] {
		t.Errorf("called=%v allowed=%v, want both actions allowed", called, allowed)
	}
}

func TestAuthorizeAnyDeniesWhenNoneAllowed(t *testing.T) {
	code, called, _ := runAuthorizeAny(t, &actionPDP{allowed: map[string]bool{}}, authz.FailClosed)
	if called || code != http.StatusForbidden {
		t.Errorf("code=%d called=%v, want 403 and next not called", code, called)
	}
}

func TestAuthorizeAnyEvaluationErrorIs500(t *testing.T) {
	code, called, _ := runAuthorizeAny(t, &actionPDP{err: errors.New("boom")}, authz.FailClosed)
	if called || code != http.StatusInternalServerError {
		t.Errorf("code=%d called=%v, want 500", code, called)
	}
}

func TestAuthorizeAnyFailModes(t *testing.T) {
	unavailable := &actionPDP{err: authz.ErrUnavailable}
	code, called, _ := runAuthorizeAny(t, unavailable, authz.FailClosed)
	if called || code != http.StatusForbidden {
		t.Errorf("fail-closed: code=%d called=%v, want 403", code, called)
	}
	code, called, allowed := runAuthorizeAny(t, unavailable, authz.FailOpen)
	if !called || code != http.StatusOK {
		t.Fatalf("fail-open: code=%d called=%v, want next called", code, called)
	}
	if len(allowed) != 0 {
		t.Errorf("fail-open must not record any action as allowed, got %v", allowed)
	}
}

func TestAllowedActionsWithoutAuthorizeAny(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", http.NoBody), httptest.NewRecorder())
	if got := AllowedActions(c); got[authz.ActionConfigure] {
		t.Errorf("AllowedActions on an unguarded route = %v, want nothing allowed", got)
	}
}
