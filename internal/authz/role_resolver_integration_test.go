//go:build integration

package authz

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// grant inserts a persisted role assignment, normalizing the assignee id exactly as the write
// API does so the resolver's lower-cased lookups match.
func grant(t *testing.T, db *gorm.DB, assigneeType, assigneeID, role, source string) {
	t.Helper()
	require.NoError(t, db.Create(&relational.CCFRoleAssignment{
		RoleName:     role,
		AssigneeType: assigneeType,
		AssigneeID:   relational.NormalizeAssigneeID(assigneeID),
		Source:       source,
	}).Error)
}

// TestDBRoleResolverMatchesFileBehaviour is the BCH-1333 parity check at the resolver level:
// for an equivalent fixture, resolving roles from the ccf_role_assignments table yields exactly
// what the previous file-based RoleAssignments.rolesFor produced — for direct grants, group
// grants, their union, and the agent/anonymous defaults the table does not hold.
func TestDBRoleResolverMatchesFileBehaviour(t *testing.T) {
	db := setupAuthzDB(t)

	// File-based fixture (the behaviour we must reproduce).
	file := &RoleAssignments{
		Users:  map[string]string{"alice@example.com": "viewer"},
		Groups: map[string]string{"sec-team": "auditor", "ops": "admin"},
		Agents: "agent",
	}
	file.normalize()

	// Equivalent table fixture: the same user/group grants persisted. The defaults passed to the
	// resolver carry only the agent role (the table holds no agent/anonymous rows).
	grant(t, db, relational.RoleAssigneeTypeUser, "Alice@Example.com", "viewer", relational.RoleAssignmentSourceManual)
	grant(t, db, relational.RoleAssigneeTypeGroup, "Sec-Team", "auditor", relational.RoleAssignmentSourceManual)
	grant(t, db, relational.RoleAssigneeTypeGroup, "ops", "admin", relational.RoleAssignmentSourceManual)

	defaults := &RoleAssignments{Agents: "agent"}
	defaults.normalize()
	// ttl 0 disables caching so each case is a fresh table read.
	resolver := NewDBRoleResolver(db, defaults, 0, zap.NewNop().Sugar())

	cases := []struct {
		name string
		subj Subject
	}{
		{"direct user grant, case-insensitive", Subject{Type: "user", ID: "Alice@Example.com"}},
		{"unassigned user, deny-by-default", Subject{Type: "user", ID: "nobody@example.com"}},
		{"group grant via groups prop", Subject{Type: "user", ID: "x@example.com", Props: map[string]any{"groups": []string{"sec-team"}}}},
		{"union of direct + groups, sorted+deduped", Subject{Type: "user", ID: "alice@example.com", Props: map[string]any{"groups": []any{"sec-team", "ops"}}}},
		{"agent default", Subject{Type: "agent", ID: "agent-1"}},
		{"anonymous, deny-by-default", Subject{Type: "anonymous"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, _ := file.RolesFor(context.Background(), tc.subj)
			got, err := resolver.RolesFor(context.Background(), tc.subj)
			require.NoError(t, err)
			require.Equal(t, want, got, "table resolution must match file behaviour")
		})
	}
}

// TestDBRoleResolverNilDBFallsBackToDefaults proves a deployment without a DB keeps working: the
// static defaults are returned directly, so the constructor can be wired unconditionally.
func TestDBRoleResolverNilDBFallsBackToDefaults(t *testing.T) {
	defaults := &RoleAssignments{Users: map[string]string{"a@b.com": "viewer"}, Agents: "agent"}
	defaults.normalize()
	resolver := NewDBRoleResolver(nil, defaults, time.Second, zap.NewNop().Sugar())

	roles, err := resolver.RolesFor(context.Background(), Subject{Type: "user", ID: "a@b.com"})
	require.NoError(t, err)
	require.Equal(t, []string{"viewer"}, roles)
}

// TestDBRoleResolverCacheServesWithinTTL proves the short-TTL cache absorbs repeat lookups: a
// grant inserted after the first resolution is not seen until the entry expires.
func TestDBRoleResolverCacheServesWithinTTL(t *testing.T) {
	db := setupAuthzDB(t)
	grant(t, db, relational.RoleAssigneeTypeUser, "alice@example.com", "viewer", relational.RoleAssignmentSourceManual)

	resolver := NewDBRoleResolver(db, &RoleAssignments{Agents: "agent"}, time.Minute, zap.NewNop().Sugar())
	subj := Subject{Type: "user", ID: "alice@example.com"}

	first, err := resolver.RolesFor(context.Background(), subj)
	require.NoError(t, err)
	require.Equal(t, []string{"viewer"}, first)

	// A second grant lands after the cache entry was populated; the cached value is served.
	grant(t, db, relational.RoleAssigneeTypeUser, "alice@example.com", "admin", relational.RoleAssignmentSourceManual)
	cached, err := resolver.RolesFor(context.Background(), subj)
	require.NoError(t, err)
	require.Equal(t, []string{"viewer"}, cached, "within TTL the cached roles are served")

	// With caching disabled (ttl 0) the fresh read sees both grants.
	fresh := NewDBRoleResolver(db, &RoleAssignments{Agents: "agent"}, 0, zap.NewNop().Sugar())
	roles, err := fresh.RolesFor(context.Background(), subj)
	require.NoError(t, err)
	require.Equal(t, []string{"admin", "viewer"}, roles)
}
