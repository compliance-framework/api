package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPDP answers Evaluations from an allow predicate (or an error), recording the batch
// size so the test can assert a single batched enumeration.
type stubPDP struct {
	allow     func(action string) bool
	err       error
	lastBatch int
}

func (s *stubPDP) Evaluate(context.Context, authz.Subject, string, authz.Resource, map[string]any) (authz.Decision, error) {
	return authz.Decision{}, nil
}

func (s *stubPDP) Evaluations(_ context.Context, reqs []authz.EvalRequest) ([]authz.Decision, error) {
	s.lastBatch = len(reqs)
	if s.err != nil {
		return nil, s.err
	}
	out := make([]authz.Decision, len(reqs))
	for i, r := range reqs {
		out[i] = authz.Decision{Allow: s.allow(r.Action)}
	}
	return out, nil
}

func newPermissionsCtx(t *testing.T, subject string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/me/permissions", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if subject != "" {
		c.Set("user", &authn.UserClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: subject}})
	}
	return c, rec
}

func manifestForTest(t *testing.T) *authz.Manifest {
	t.Helper()
	m, err := authz.DefaultManifest()
	require.NoError(t, err)
	return m
}

func decodeResp(t *testing.T, rec *httptest.ResponseRecorder) permissionsResponse {
	t.Helper()
	var resp permissionsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// TestPermissionsAllowedSubset: a PDP that only allows "read" yields exactly the read
// actions per resource, in one batched call, with every resource present in the response.
func TestPermissionsAllowedSubset(t *testing.T) {
	m := manifestForTest(t)
	pdp := &stubPDP{allow: func(action string) bool { return action == "read" }}
	h := NewPermissionsHandler(pdp, m, authz.FailClosed, nil)

	c, rec := newPermissionsCtx(t, "alice@acme.com")
	require.NoError(t, h.GetPermissions(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeResp(t, rec)
	assert.Equal(t, "user", resp.Subject.Type)
	assert.Equal(t, "alice@acme.com", resp.Subject.ID)

	// Every manifest resource is present; only "read" survives where it's a declared action.
	totalActions := 0
	for name, def := range m.Resources {
		got, ok := resp.Permissions[name]
		require.Truef(t, ok, "resource %q missing from response", name)
		totalActions += len(def.Actions)
		hasRead := false
		for _, a := range def.Actions {
			if a == "read" {
				hasRead = true
			}
		}
		if hasRead {
			assert.Equalf(t, []string{"read"}, got, "resource %q allowed actions", name)
		} else {
			assert.Emptyf(t, got, "resource %q should have no allowed actions", name)
		}
	}
	assert.Equal(t, totalActions, pdp.lastBatch, "should enumerate every resource×action in one batch")
}

func TestPermissionsFailClosed(t *testing.T) {
	m := manifestForTest(t)
	pdp := &stubPDP{err: fmt.Errorf("pdp gone: %w", authz.ErrUnavailable)}
	h := NewPermissionsHandler(pdp, m, authz.FailClosed, nil)

	c, rec := newPermissionsCtx(t, "alice@acme.com")
	require.NoError(t, h.GetPermissions(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeResp(t, rec)
	for name := range m.Resources {
		assert.Emptyf(t, resp.Permissions[name], "fail-closed must deny %q", name)
	}
}

func TestPermissionsFailOpen(t *testing.T) {
	m := manifestForTest(t)
	pdp := &stubPDP{err: fmt.Errorf("pdp gone: %w", authz.ErrUnavailable)}
	h := NewPermissionsHandler(pdp, m, authz.FailOpen, nil)

	c, rec := newPermissionsCtx(t, "alice@acme.com")
	require.NoError(t, h.GetPermissions(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeResp(t, rec)
	for name, def := range m.Resources {
		assert.ElementsMatchf(t, def.Actions, resp.Permissions[name],
			"fail-open must advertise the full vocabulary for %q", name)
	}
}

// TestPermissionsInternalError: a non-unavailable PDP error is a 500, not a silent allow.
func TestPermissionsInternalError(t *testing.T) {
	m := manifestForTest(t)
	pdp := &stubPDP{err: fmt.Errorf("boom")}
	h := NewPermissionsHandler(pdp, m, authz.FailClosed, nil)

	c, _ := newPermissionsCtx(t, "alice@acme.com")
	err := h.GetPermissions(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok, "want *echo.HTTPError")
	assert.Equal(t, http.StatusInternalServerError, he.Code)
}

// TestPermissionsAnonymousSubject: no claims → anonymous subject, still answered.
func TestPermissionsAnonymousSubject(t *testing.T) {
	m := manifestForTest(t)
	pdp := &stubPDP{allow: func(string) bool { return false }}
	h := NewPermissionsHandler(pdp, m, authz.FailClosed, nil)

	c, rec := newPermissionsCtx(t, "")
	require.NoError(t, h.GetPermissions(c))
	resp := decodeResp(t, rec)
	assert.Equal(t, "anonymous", resp.Subject.Type)
}
