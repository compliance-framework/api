package relational

import (
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// UserGroup is a native, CCF-managed group of users. It exists so group-based authorization
// works for every user regardless of auth method: a native group's membership is unioned
// with the IdP groups synced via SSOUserLink to form the source-agnostic subject.groups
// attribute (BCH-1328, BCH-1319 §7). The table is named ccf_groups; the "User" prefix on the
// Go type avoids colliding with the OSCAL catalog Group (relational.Group).
type UserGroup struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`

	// Name is the group's policy-facing identifier — the token that appears in
	// subject.groups and that role-assignment config matches on. Unique among live groups.
	Name        string `json:"name" gorm:"uniqueIndex:idx_ccf_groups_name,WHERE:deleted_at IS NULL;not null"`
	Description string `json:"description"`
}

func (UserGroup) TableName() string {
	return "ccf_groups"
}

// UserGroupMembership joins a CCF user to a native UserGroup. The (UserID, GroupID) pair is
// unique so a user appears in a group at most once. It is a hard-delete join table (removing
// a member deletes the row); the group and the user themselves are soft-deletable.
type UserGroupMembership struct {
	UUIDModel

	CreatedAt time.Time `json:"createdAt"`

	UserID  string `json:"userId" gorm:"not null;uniqueIndex:idx_ccf_user_groups_user_group,priority:1"`
	GroupID string `json:"groupId" gorm:"not null;uniqueIndex:idx_ccf_user_groups_user_group,priority:2;index"`

	Group UserGroup `json:"group,omitempty" gorm:"foreignKey:GroupID;references:ID"`
}

func (UserGroupMembership) TableName() string {
	return "ccf_user_groups"
}

// SSOGroupMapping unifies an external IdP group with a native UserGroup so a synced SSO group
// and a native group denote the same membership instead of colliding. When the group
// resolver sees the (Provider, ExternalGroup) pair on a user's SSO link it contributes the
// mapped native group's Name to subject.groups. Optional: unmapped SSO groups still pass
// through under their raw name.
type SSOGroupMapping struct {
	UUIDModel

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Provider      string `json:"provider" gorm:"not null;uniqueIndex:idx_ccf_sso_group_mappings_provider_group,priority:1"`
	ExternalGroup string `json:"externalGroup" gorm:"not null;uniqueIndex:idx_ccf_sso_group_mappings_provider_group,priority:2"`
	GroupID       string `json:"groupId" gorm:"not null;index"`

	Group UserGroup `json:"group,omitempty" gorm:"foreignKey:GroupID;references:ID"`
}

func (SSOGroupMapping) TableName() string {
	return "ccf_sso_group_mappings"
}

// GroupNamesForUser returns the names of the native CCF groups the user belongs to, sorted
// and de-duplicated. It is the single native-membership query shared by the authz group
// resolver (which unions it with SSO groups for subject.groups) and the builtin admin check
// (which folds it into its admin-group set). Returns an empty slice when the user has no
// native memberships.
//
// It resolves in two steps rather than a join because ccf_user_groups.group_id is text while
// ccf_groups.id is uuid: a column-to-column uuid = text comparison fails in Postgres (see the
// join-table mismatch in the migrator). A string IN clause sidesteps it — the group_id
// literals coerce to the uuid column cleanly on Postgres and compare as text on SQLite — and
// soft-deleted groups are excluded automatically by the gorm DeletedAt scope.
func GroupNamesForUser(db *gorm.DB, userID string) ([]string, error) {
	if strings.TrimSpace(userID) == "" {
		return []string{}, nil
	}
	var groupIDs []string
	if err := db.Model(&UserGroupMembership{}).
		Where("user_id = ?", userID).
		Pluck("group_id", &groupIDs).Error; err != nil {
		return nil, err
	}
	if len(groupIDs) == 0 {
		return []string{}, nil
	}
	var names []string
	if err := db.Model(&UserGroup{}).
		Where("id IN ?", groupIDs).
		Order("name ASC").
		Pluck("name", &names).Error; err != nil {
		return nil, err
	}
	return dedupeSortedStrings(names), nil
}

// dedupeSortedStrings returns the unique values of in, sorted ascending.
func dedupeSortedStrings(in []string) []string {
	out := make([]string, 0, len(in))
	if len(in) == 0 {
		return out
	}
	sort.Strings(in)
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
			last = s
		}
	}
	return out
}
