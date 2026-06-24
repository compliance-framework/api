package authz

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/compliance-framework/api/internal/service/relational"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// roleAssignmentKey is the (assigneeType, assigneeId, roleName) triple the table's unique index is
// built on — the identity of a single grant, exactly as the precedence rule defines it ("a grant is
// config OR manual, keyed by the triple"). Reconciliation compares grants by this key, never by
// principal, so a principal may hold a config grant for one role and a manual grant for another.
type roleAssignmentKey struct {
	assigneeType string
	assigneeID   string
	role         string
}

func keyOf(a relational.CCFRoleAssignment) roleAssignmentKey {
	return roleAssignmentKey{assigneeType: a.AssigneeType, assigneeID: a.AssigneeID, role: a.RoleName}
}

// configGrants returns the user/group role grants the file declares as (type,id,role) triples, with
// ids normalized to lower-case (matching how the table stores and looks them up), sorted for
// deterministic creation and logging. The agents/anonymous scalar defaults are intentionally
// excluded: they are not table-backed and stay config-sourced in the resolver (the BCH-1333
// decision). normalize() must have run first, so map keys are already folded.
func (ra *RoleAssignments) configGrants() []roleAssignmentKey {
	grants := make([]roleAssignmentKey, 0, len(ra.Users)+len(ra.Groups))
	add := func(assigneeType, principal, role string) {
		if role == "" {
			return
		}
		grants = append(grants, roleAssignmentKey{
			assigneeType: assigneeType,
			assigneeID:   relational.NormalizeAssigneeID(principal),
			role:         role,
		})
	}
	for user, role := range ra.Users {
		add(relational.RoleAssigneeTypeUser, user, role)
	}
	for group, role := range ra.Groups {
		add(relational.RoleAssigneeTypeGroup, group, role)
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].assigneeType != grants[j].assigneeType {
			return grants[i].assigneeType < grants[j].assigneeType
		}
		if grants[i].assigneeID != grants[j].assigneeID {
			return grants[i].assigneeID < grants[j].assigneeID
		}
		return grants[i].role < grants[j].role
	})
	return grants
}

// ReconcileConfigRoleAssignments makes the persisted ccf_role_assignments table reflect the
// user/group grants declared in the role-assignment config file (authz-roles.yaml), marking them
// source=config (BCH-1334). With BCH-1333 the table is the PDP's source of truth, so the file stops
// being read per request and is instead a boot seed reconciled into the table here.
//
// Reconcile, don't duplicate:
//   - a config grant that already matches is left untouched (no write);
//   - a grant the file no longer declares is deleted (source=config rows only);
//   - a manual row whose (type,id,role) the file now declares is adopted as config — precedence:
//     config ownership wins for an identical grant, so the admin API's 409-on-config-delete protects
//     it and the file/API never fight over the same row;
//   - source=manual rows the file does not declare are never touched.
//
// It is idempotent: re-running the same file produces zero writes and no duplicate rows. A missing
// file is "no config grants" — every source=config row is removed — so deleting the file revokes its
// grants on the next boot. A malformed file, or a role the manifest does not declare, is a hard error
// that blocks startup (the caller treats a migration error as fatal), preserving the fail-fast
// validate() behaviour the cedar loader had. It runs for every driver so the table, and the admin UI
// built on it, reflect config regardless of which engine enforces it.
func ReconcileConfigRoleAssignments(ctx context.Context, db *gorm.DB, path string, logger *zap.SugaredLogger) error {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	if db == nil {
		return nil
	}

	assignments := &RoleAssignments{}
	if path != "" {
		loaded, err := LoadRoleAssignments(path)
		switch {
		case err == nil:
			assignments = loaded
		case errors.Is(err, fs.ErrNotExist):
			logger.Infow("authz reconcile: role-assignment file not found; removing any config-owned grants", "path", path)
		default:
			return err
		}
	}
	assignments.normalize()

	m, err := DefaultManifest()
	if err != nil {
		return fmt.Errorf("authz reconcile: load manifest: %w", err)
	}
	if err := assignments.validate(m); err != nil {
		return err
	}

	desired := assignments.configGrants()
	desiredSet := make(map[roleAssignmentKey]struct{}, len(desired))
	for _, want := range desired {
		desiredSet[want] = struct{}{}
	}

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing []relational.CCFRoleAssignment
		if err := tx.Find(&existing).Error; err != nil {
			return err
		}
		byTriple := make(map[roleAssignmentKey]relational.CCFRoleAssignment, len(existing))
		for _, row := range existing {
			byTriple[keyOf(row)] = row
		}

		var created, adopted, deleted int
		for _, want := range desired {
			row, ok := byTriple[want]
			switch {
			case !ok:
				// OnConflict DoNothing keeps the insert idempotent under concurrent boots: this
				// reconcile runs on every replica's startup (MigrateUpWithConfig, fatal on error), so in
				// an HA/rolling deploy two replicas can both see the triple as absent and race to insert
				// it. Without this, the loser's commit raises a duplicate-key violation that crashes the
				// replica (CrashLoopBackOff) for a benign race; with it, the loser is a no-op. The unique
				// index is (assignee_type, assignee_id, role_name).
				if err := tx.Clauses(clause.OnConflict{
					Columns: []clause.Column{
						{Name: "assignee_type"},
						{Name: "assignee_id"},
						{Name: "role_name"},
					},
					DoNothing: true,
				}).Create(&relational.CCFRoleAssignment{
					RoleName:     want.role,
					AssigneeType: want.assigneeType,
					AssigneeID:   want.assigneeID,
					Source:       relational.RoleAssignmentSourceConfig,
				}).Error; err != nil {
					return err
				}
				created++
			case row.Source != relational.RoleAssignmentSourceConfig:
				// An identical manual grant already exists; config ownership wins, so adopt it as
				// config rather than creating a duplicate (which the unique index would reject anyway).
				if err := tx.Model(&relational.CCFRoleAssignment{}).
					Where("id = ?", row.ID).
					Update("source", relational.RoleAssignmentSourceConfig).Error; err != nil {
					return err
				}
				adopted++
			}
			// else: already source=config and matching — leave untouched (this is what makes a
			// re-run of an unchanged file write nothing).
		}

		for _, row := range existing {
			if row.Source != relational.RoleAssignmentSourceConfig {
				continue
			}
			if _, ok := desiredSet[keyOf(row)]; ok {
				continue
			}
			if err := tx.Delete(&row).Error; err != nil {
				return err
			}
			deleted++
		}

		if created+adopted+deleted > 0 {
			logger.Infow("authz reconcile: synced config role assignments",
				"created", created, "adopted", adopted, "deleted", deleted, "configGrants", len(desired))
		}
		return nil
	})
}
