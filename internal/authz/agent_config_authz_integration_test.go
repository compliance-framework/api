//go:build integration

package authz

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// R53: a user's effective Cedar roles are the union of their direct assignment and one
// assignment per native group they belong to, as resolved through the production wiring
// (DB role resolver + DB group PIP).
func TestUserAndGroupGrantsCombine(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "u@x.example", "password")
	grant(t, db, relational.RoleAssigneeTypeUser, user.Email, "viewer", relational.RoleAssignmentSourceManual)
	grant(t, db, relational.RoleAssigneeTypeGroup, "ccf-contributors", "contributor", relational.RoleAssignmentSourceManual)
	addNativeGroup(t, db, user, "ccf-contributors")

	m, err := DefaultManifest()
	require.NoError(t, err)
	policies, err := CompileRolePolicies(m)
	require.NoError(t, err)
	defaults := &RoleAssignments{Agents: DefaultAgentRole}
	defaults.normalize()
	const ttl = 50 * time.Millisecond
	cedarPDP := NewCedar(policies, NewDBRoleResolver(db, defaults, ttl, zap.NewNop().Sugar()), zap.NewNop().Sugar())
	pdp := newResolvingPDP(cedarPDP, NewDBGroupResolver(db, zap.NewNop().Sugar()), zap.NewNop().Sugar())

	subject := Subject{Type: "user", ID: user.Email}
	allow := func(action, resource string) bool {
		t.Helper()
		d, err := pdp.Evaluate(context.Background(), subject, action, Resource{Type: resource}, nil)
		require.NoError(t, err)
		return d.Allow
	}

	require.True(t, allow(ActionCreate, ResourceCatalog), "catalog create via the group grant")
	require.True(t, allow(ActionRead, ResourceCatalog), "catalog read via the direct viewer grant")
	require.False(t, allow(ActionConfigure, ResourceAgent), "configure is in neither grant")

	// Remove the membership; once the role cache expires the group grant no longer applies.
	require.NoError(t, db.Where("user_id = ?", user.ID.String()).Delete(&relational.UserGroupMembership{}).Error)
	time.Sleep(2 * ttl)
	require.False(t, allow(ActionCreate, ResourceCatalog), "catalog create without the membership")
	require.True(t, allow(ActionRead, ResourceCatalog), "the direct viewer grant still applies")
}

// R39: under the builtin driver a user on the agent resource needs the admin check, so an SSO
// user without the required admin group is denied every agent action, while a password user
// (super admin) is allowed.
func TestBuiltinAgentResourceRequiresAdminForUsers(t *testing.T) {
	db := setupAuthzDB(t)
	cfg := ssoEnabledConfig([]string{"ccf-admins"})
	ssoUser := createUser(t, db, "sso@x.example", "sso")
	createSSOLink(t, db, ssoUser, "test", []string{"engineering"})
	createUser(t, db, "pw@x.example", "password")

	b := NewBuiltin(db, cfg, zap.NewNop().Sugar())
	for _, action := range []string{ActionRead, ActionConfigure} {
		dec, err := b.Evaluate(context.Background(), Subject{Type: "user", ID: ssoUser.Email}, action, Resource{Type: ResourceAgent}, nil)
		require.NoError(t, err)
		require.False(t, dec.Allow, "SSO non-admin %s on agent must be denied", action)

		dec, err = b.Evaluate(context.Background(), Subject{Type: "user", ID: "pw@x.example"}, action, Resource{Type: ResourceAgent}, nil)
		require.NoError(t, err)
		require.True(t, dec.Allow, "password user %s on agent must be allowed", action)
	}

	adminUser := createUser(t, db, "admin@x.example", "sso")
	createSSOLink(t, db, adminUser, "test", []string{"ccf-admins"})
	dec, err := b.Evaluate(context.Background(), Subject{Type: "user", ID: adminUser.Email}, ActionConfigure, Resource{Type: ResourceAgent}, nil)
	require.NoError(t, err)
	require.True(t, dec.Allow, "SSO admin-group member must be allowed")
}
