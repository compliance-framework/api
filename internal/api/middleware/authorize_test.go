package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type stubPDP struct {
	decision    authz.Decision
	err         error
	called      bool
	gotSubject  authz.Subject
	gotAction   string
	gotResource authz.Resource
	gotCtx      map[string]any
}

func (s *stubPDP) Evaluate(_ context.Context, subj authz.Subject, action string, res authz.Resource, reqCtx map[string]any) (authz.Decision, error) {
	s.called = true
	s.gotSubject = subj
	s.gotAction = action
	s.gotResource = res
	s.gotCtx = reqCtx
	return s.decision, s.err
}

func (s *stubPDP) Evaluations(context.Context, []authz.EvalRequest) ([]authz.Decision, error) {
	return nil, nil
}

func newTestContext(method string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, "/api/evidence", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func runAuthorize(t *testing.T, a *Authorizer, c echo.Context, opts ...AuthorizeOption) (bool, error) {
	t.Helper()
	nextCalled := false
	h := a.Authorize("evidence", "create", opts...)(func(c echo.Context) error {
		nextCalled = true
		return c.NoContent(http.StatusOK)
	})
	return nextCalled, h(c)
}

func httpStatus(t *testing.T, err error) int {
	t.Helper()
	he := &echo.HTTPError{}
	require.Truef(t, errors.As(err, &he), "expected *echo.HTTPError, got %T", err)
	return he.Code
}

func TestAuthorize_Allow(t *testing.T) {
	a := NewAuthorizer(&stubPDP{decision: authz.Decision{Allow: true}}, zap.NewNop().Sugar(), authz.FailClosed)
	c, rec := newTestContext(http.MethodPost)
	called, err := runAuthorize(t, a, c)
	require.NoError(t, err)
	require.True(t, called)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthorize_Deny(t *testing.T) {
	a := NewAuthorizer(&stubPDP{decision: authz.Decision{Allow: false, Reason: "nope"}}, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodPost)
	called, err := runAuthorize(t, a, c)
	require.False(t, called)
	require.Equal(t, http.StatusForbidden, httpStatus(t, err))
}

func TestAuthorize_ErrorFailClosed(t *testing.T) {
	a := NewAuthorizer(&stubPDP{err: errors.New("boom")}, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodPost)
	called, err := runAuthorize(t, a, c)
	require.False(t, called)
	require.Equal(t, http.StatusInternalServerError, httpStatus(t, err))
}

func TestAuthorize_ErrorFailOpen(t *testing.T) {
	a := NewAuthorizer(&stubPDP{err: errors.New("boom")}, zap.NewNop().Sugar(), authz.FailOpen)
	c, rec := newTestContext(http.MethodPost)
	called, err := runAuthorize(t, a, c)
	require.NoError(t, err)
	require.True(t, called)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthorize_OptionsSkipsPDP(t *testing.T) {
	stub := &stubPDP{decision: authz.Decision{Allow: false}}
	a := NewAuthorizer(stub, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodOptions)
	called, err := runAuthorize(t, a, c)
	require.NoError(t, err)
	require.True(t, called)
	require.False(t, stub.called, "PDP must not be consulted for CORS preflight")
}

func TestAuthorize_NilPDPDenies(t *testing.T) {
	a := NewAuthorizer(nil, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodPost)
	called, err := runAuthorize(t, a, c)
	require.False(t, called)
	require.Equal(t, http.StatusForbidden, httpStatus(t, err))
}

func TestAuthorize_BuildsUserSubject(t *testing.T) {
	stub := &stubPDP{decision: authz.Decision{Allow: true}}
	a := NewAuthorizer(stub, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodPost)
	c.Set("user", &authn.UserClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "alice@example.com"}})
	_, err := runAuthorize(t, a, c)
	require.NoError(t, err)
	require.Equal(t, authz.SubjectUser, stub.gotSubject.Type)
	require.Equal(t, "alice@example.com", stub.gotSubject.ID)
	require.Equal(t, "alice@example.com", stub.gotSubject.Props["email"])
}

func TestAuthorize_BuildsAgentSubject(t *testing.T) {
	stub := &stubPDP{decision: authz.Decision{Allow: true}}
	a := NewAuthorizer(stub, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodPost)
	c.Set("agent_claims", &authn.AgentClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "client-1"}, AgentID: "agent-1"})
	_, err := runAuthorize(t, a, c)
	require.NoError(t, err)
	require.Equal(t, authz.SubjectAgent, stub.gotSubject.Type)
	require.Equal(t, "client-1", stub.gotSubject.ID)
	require.Equal(t, "agent-1", stub.gotSubject.Props["agent_id"])
}

func TestAuthorize_AnonymousSubject(t *testing.T) {
	stub := &stubPDP{decision: authz.Decision{Allow: true}}
	a := NewAuthorizer(stub, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodPost)
	_, err := runAuthorize(t, a, c)
	require.NoError(t, err)
	require.Equal(t, authz.SubjectAnonymous, stub.gotSubject.Type)
}

func TestAuthorize_PassesContextAndResource(t *testing.T) {
	stub := &stubPDP{decision: authz.Decision{Allow: true}}
	a := NewAuthorizer(stub, zap.NewNop().Sugar(), authz.FailClosed)
	c, _ := newTestContext(http.MethodPost)
	_, err := runAuthorize(t, a, c, WithPublicAccess(true))
	require.NoError(t, err)
	require.Equal(t, true, stub.gotCtx["allow_public"])
	require.Equal(t, "create", stub.gotAction)
	require.Equal(t, "evidence", stub.gotResource.Type)
}
