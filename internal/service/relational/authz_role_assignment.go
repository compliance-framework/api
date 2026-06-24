package relational

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// Role-assignment assignee discriminators. A grant targets either a single user (matched by
// email, the subject identifier authz carries) or a native group (matched by the group's
// policy-facing Name, the token that appears in subject.groups). These mirror the in-memory
// RoleAssignments.Users / .Groups maps the persisted table supersedes (BCH-1333).
const (
	// RoleAssigneeTypeUser targets a user by email.
	RoleAssigneeTypeUser = "user"
	// RoleAssigneeTypeGroup targets a native CCF group by name.
	RoleAssigneeTypeGroup = "group"
)

// Role-assignment source discriminators. config and manual grants are the same rows,
// distinguished only by who owns them: config grants are seeded from authz-roles.yaml by the
// boot reconcile (BCH-1334) and are immutable through the API; manual grants are ad-hoc admin
// grants and are the only ones the API may delete.
const (
	// RoleAssignmentSourceConfig is a grant materialized from authz-roles.yaml. It is managed by
	// the boot reconcile (BCH-1334) and cannot be deleted through the admin API (409).
	RoleAssignmentSourceConfig = "config"
	// RoleAssignmentSourceManual is an ad-hoc admin grant. It is the default for API-created rows
	// and the only source the admin API may delete.
	RoleAssignmentSourceManual = "manual"
)

// CCFRoleAssignment is a persisted system-level role grant: it binds one manifest role to one
// user or group, system-wide (BCH-1333). It is the source of truth the PDP reads a subject's
// roles from (behind a short-TTL cache, see authz.NewDBRoleResolver), replacing the in-memory
// authz-roles.yaml. It is deliberately distinct from the workflow-instance-scoped
// role_assignments table (workflows.RoleAssignment): those grant a step persona within one
// workflow instance, these grant a global RBAC role.
//
// AssigneeID is normalized to lower-case at write time (emails and group names are matched
// case-insensitively, exactly as the file-based assignments folded their keys), so the unique
// index and the PDP lookups both compare exact lower-case values.
type CCFRoleAssignment struct {
	UUIDModel

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// RoleName is a manifest role (admin/viewer/auditor/contributor/agent or an operator role).
	// The handler validates it against the authz manifest before insert so a typo is rejected
	// rather than silently granting nothing.
	RoleName string `json:"roleName" gorm:"not null;uniqueIndex:idx_ccf_role_assignments_unique,priority:3"`

	// AssigneeType is RoleAssigneeTypeUser or RoleAssigneeTypeGroup.
	AssigneeType string `json:"assigneeType" gorm:"not null;uniqueIndex:idx_ccf_role_assignments_unique,priority:1"`

	// AssigneeID is the user email or the group name, normalized to lower-case.
	AssigneeID string `json:"assigneeId" gorm:"not null;uniqueIndex:idx_ccf_role_assignments_unique,priority:2"`

	// Source is RoleAssignmentSourceConfig (immutable, owned by BCH-1334) or
	// RoleAssignmentSourceManual (admin-owned, deletable). Defaults to manual so an API insert
	// that omits it is an ad-hoc grant.
	Source string `json:"source" gorm:"not null;default:manual"`
}

func (CCFRoleAssignment) TableName() string {
	return "ccf_role_assignments"
}

// NormalizeAssigneeID folds an assignee identifier (email or group name) to the trimmed,
// lower-cased form stored in and matched against the table, so case never splits a grant.
func NormalizeAssigneeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// RoleNamesForAssignee returns the (sorted, de-duplicated) role names granted directly to one
// assignee. assigneeID is normalized before the lookup, so callers may pass a raw email or
// group name. It is the single-assignee query the group/user effective-role reads share.
func RoleNamesForAssignee(db *gorm.DB, assigneeType, assigneeID string) ([]string, error) {
	var names []string
	if err := db.Model(&CCFRoleAssignment{}).
		Where("assignee_type = ? AND assignee_id = ?", assigneeType, NormalizeAssigneeID(assigneeID)).
		Pluck("role_name", &names).Error; err != nil {
		return nil, err
	}
	return dedupeSortedStrings(names), nil
}
