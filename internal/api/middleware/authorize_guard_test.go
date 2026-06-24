package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// runGuarded runs a single ResourceGuard-produced middleware against a request from the given
// authenticated user, returning the HTTP status and whether the wrapped handler ran.
func runGuarded(t *testing.T, subjectID string, mw echo.MiddlewareFunc) (int, bool) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/risks", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user", &authn.UserClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: subjectID}})

	called := false
	next := func(c echo.Context) error { called = true; return c.NoContent(http.StatusOK) }
	if err := mw(next)(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec.Code, called
}

func mustCedarPDP(t *testing.T, ra *authz.RoleAssignments) authz.PDP {
	t.Helper()
	m, err := authz.DefaultManifest()
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	policies, err := authz.CompileRolePolicies(m)
	if err != nil {
		t.Fatalf("compile policies: %v", err)
	}
	return authz.NewCedar(policies, ra, nil)
}

// TestResourceGuardBuiltinVsCedar is the core of the route-wiring fix: the SAME guarded route
// is a no-op under the builtin driver (every authenticated non-admin request allowed) but
// enforced per (resource, action) under cedar. Before the fix most routes never reached the
// PDP at all, so cedar could not enforce them.
func TestResourceGuardBuiltinVsCedar(t *testing.T) {
	// builtin: a risk read by an authenticated user is allowed without consulting roles
	// (db/cfg are nil because the non-admin path never touches them).
	builtinGuard := NewPEP(authz.NewBuiltin(nil, nil, nil), authz.FailClosed, nil).For(authz.ResourceRisk)
	if code, called := runGuarded(t, "anyone@example.com", builtinGuard.Read()); !called || code != http.StatusOK {
		t.Fatalf("builtin risk read: code=%d called=%v, want 200/true", code, called)
	}

	// cedar with no role assignments: deny-by-default — a user with no role is forbidden.
	noRoleGuard := NewPEP(mustCedarPDP(t, &authz.RoleAssignments{}), authz.FailClosed, nil).For(authz.ResourceRisk)
	if code, called := runGuarded(t, "norole@example.com", noRoleGuard.Read()); called || code != http.StatusForbidden {
		t.Fatalf("cedar risk read (no role): code=%d called=%v, want 403/false", code, called)
	}

	// cedar with a viewer role: read is granted, but create (a write) is denied — proving the
	// per-route action mapping is what cedar actually enforces.
	viewerPEP := NewPEP(mustCedarPDP(t, &authz.RoleAssignments{Users: map[string]string{"viewer@example.com": "viewer"}}), authz.FailClosed, nil)
	viewerGuard := viewerPEP.For(authz.ResourceRisk)
	if code, called := runGuarded(t, "viewer@example.com", viewerGuard.Read()); !called || code != http.StatusOK {
		t.Fatalf("cedar viewer risk read: code=%d called=%v, want 200/true", code, called)
	}
	if code, called := runGuarded(t, "viewer@example.com", viewerGuard.Create()); called || code != http.StatusForbidden {
		t.Fatalf("cedar viewer risk create: code=%d called=%v, want 403/false", code, called)
	}
}
