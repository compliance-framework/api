//go:build integration

package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func writeRolesFile(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "authz-roles.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func allAssignments(t *testing.T, db *gorm.DB) []relational.CCFRoleAssignment {
	t.Helper()
	var rows []relational.CCFRoleAssignment
	require.NoError(t, db.Order("assignee_type, assignee_id, role_name").Find(&rows).Error)
	return rows
}

func indexByTriple(rows []relational.CCFRoleAssignment) map[string]relational.CCFRoleAssignment {
	out := make(map[string]relational.CCFRoleAssignment, len(rows))
	for _, r := range rows {
		out[r.AssigneeType+"|"+r.AssigneeID+"|"+r.RoleName] = r
	}
	return out
}

func idSet(rows []relational.CCFRoleAssignment) map[string]bool {
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.ID.String()] = true
	}
	return out
}

// TestReconcileConfigRoleAssignments exercises the BCH-1334 boot reconcile: the role-assignment
// file becomes source=config rows in ccf_role_assignments (BCH-1333's source of truth), kept in
// sync across restarts without churn, and never touching admin-created manual grants.
func TestReconcileConfigRoleAssignments(t *testing.T) {
	ctx := context.Background()

	t.Run("seeds config grants and is idempotent", func(t *testing.T) {
		db := setupAuthzDB(t)
		dir := t.TempDir()
		// Mixed casing on purpose: ids are normalized to lower-case at write time.
		path := writeRolesFile(t, dir, `
users:
  Alice@Example.com: auditor
  bob@example.com: admin
groups:
  Sec-Team: viewer
`)
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))

		rows := allAssignments(t, db)
		require.Len(t, rows, 3)
		for _, r := range rows {
			require.Equal(t, relational.RoleAssignmentSourceConfig, r.Source)
		}
		byKey := indexByTriple(rows)
		require.Contains(t, byKey, "user|alice@example.com|auditor")
		require.Contains(t, byKey, "user|bob@example.com|admin")
		require.Contains(t, byKey, "group|sec-team|viewer")

		// Re-running an unchanged file must write nothing: the same row ids survive (no
		// delete+recreate) and no duplicates appear.
		before := idSet(rows)
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))
		after := allAssignments(t, db)
		require.Len(t, after, 3)
		require.Equal(t, before, idSet(after), "re-running an unchanged config must not rewrite rows")
	})

	t.Run("removes config grants dropped from the file, leaves manual untouched", func(t *testing.T) {
		db := setupAuthzDB(t)
		dir := t.TempDir()
		path := writeRolesFile(t, dir, `
users:
  alice@example.com: auditor
  bob@example.com: admin
`)
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))

		// An ad-hoc admin grant, not declared in config.
		manual := &relational.CCFRoleAssignment{
			RoleName:     "viewer",
			AssigneeType: relational.RoleAssigneeTypeUser,
			AssigneeID:   "carol@example.com",
			Source:       relational.RoleAssignmentSourceManual,
		}
		require.NoError(t, db.Create(manual).Error)

		// Drop bob from the file and reconcile.
		writeRolesFile(t, dir, `
users:
  alice@example.com: auditor
`)
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))

		byKey := indexByTriple(allAssignments(t, db))
		require.Contains(t, byKey, "user|alice@example.com|auditor")
		require.NotContains(t, byKey, "user|bob@example.com|admin", "config grant dropped from the file must be deleted")

		survivor, ok := byKey["user|carol@example.com|viewer"]
		require.True(t, ok, "manual grant must survive a reconcile")
		require.Equal(t, relational.RoleAssignmentSourceManual, survivor.Source)
		require.Equal(t, manual.ID.String(), survivor.ID.String(), "manual row left untouched")
	})

	t.Run("missing file removes config grants but keeps manual", func(t *testing.T) {
		db := setupAuthzDB(t)
		dir := t.TempDir()
		path := writeRolesFile(t, dir, "users:\n  alice@example.com: auditor\n")
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))
		require.NoError(t, db.Create(&relational.CCFRoleAssignment{
			RoleName:     "viewer",
			AssigneeType: relational.RoleAssigneeTypeUser,
			AssigneeID:   "carol@example.com",
			Source:       relational.RoleAssignmentSourceManual,
		}).Error)

		require.NoError(t, os.Remove(path))
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))

		rows := allAssignments(t, db)
		require.Len(t, rows, 1)
		require.Equal(t, relational.RoleAssignmentSourceManual, rows[0].Source)
		require.Equal(t, "carol@example.com", rows[0].AssigneeID)
	})

	t.Run("adopts an identical manual grant as config (precedence)", func(t *testing.T) {
		db := setupAuthzDB(t)
		dir := t.TempDir()
		// Admin manually grants alice auditor before config declares the same triple.
		manual := &relational.CCFRoleAssignment{
			RoleName:     "auditor",
			AssigneeType: relational.RoleAssigneeTypeUser,
			AssigneeID:   "alice@example.com",
			Source:       relational.RoleAssignmentSourceManual,
		}
		require.NoError(t, db.Create(manual).Error)

		path := writeRolesFile(t, dir, "users:\n  alice@example.com: auditor\n")
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))

		rows := allAssignments(t, db)
		require.Len(t, rows, 1, "an identical grant must not be duplicated")
		require.Equal(t, relational.RoleAssignmentSourceConfig, rows[0].Source, "config ownership wins for an identical grant")
		require.Equal(t, manual.ID.String(), rows[0].ID.String(), "the existing row is adopted in place, not replaced")
	})

	t.Run("replaces a changed role for a principal (delete old + create new)", func(t *testing.T) {
		db := setupAuthzDB(t)
		dir := t.TempDir()
		path := writeRolesFile(t, dir, "users:\n  alice@example.com: auditor\n")
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))

		before := allAssignments(t, db)
		require.Len(t, before, 1)
		oldID := before[0].ID.String()

		writeRolesFile(t, dir, "users:\n  alice@example.com: admin\n")
		require.NoError(t, ReconcileConfigRoleAssignments(ctx, db, path, nil))

		rows := allAssignments(t, db)
		require.Len(t, rows, 1, "alice still has exactly one config grant after the role change")
		require.Equal(t, "admin", rows[0].RoleName)
		require.Equal(t, relational.RoleAssignmentSourceConfig, rows[0].Source)
		// The role is part of the unique triple, so a role change is delete(old triple)+create(new),
		// not an in-place row update: the row identity changes. (Contrast the adopt test, which keeps
		// the same id because the triple is unchanged.)
		require.NotEqual(t, oldID, rows[0].ID.String(), "a role change replaces the row rather than updating it in place")
	})

	t.Run("a file referencing an unknown role fails fast", func(t *testing.T) {
		db := setupAuthzDB(t)
		dir := t.TempDir()
		path := writeRolesFile(t, dir, "users:\n  alice@example.com: wizard\n")
		require.Error(t, ReconcileConfigRoleAssignments(ctx, db, path, nil), "an unknown role must block startup")

		require.Empty(t, allAssignments(t, db), "a rejected file must not write any rows")
	})
}
