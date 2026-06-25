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

	// Source records how the group came to exist: GroupSourceManual (an admin created it via the API)
	// or GroupSourceSSO (SSO provisioning materialized it from a group_mapping value). It defaults to
	// manual so admin-created and pre-attribution groups are never auto-removed. Only sso groups that
	// have become fully unreferenced are cleaned up at boot (CleanupOrphanedSSOGroups); the source is
	// set only when the group is first created, so an admin group that later appears in SSO config
	// stays manual.
	Source string `json:"source" gorm:"not null;default:manual"`
}

func (UserGroup) TableName() string {
	return "ccf_groups"
}

// Group source discriminators (see UserGroup.Source).
const (
	// GroupSourceManual is an admin-created native group. It is the default and is never auto-removed.
	GroupSourceManual = "manual"
	// GroupSourceSSO is a group materialized by SSO provisioning from a group_mapping value. It is
	// eligible for boot-time cleanup once nothing references it (no mapping, no members, no grants).
	GroupSourceSSO = "sso"
)

// Membership source discriminators (BCH-1331). A membership records how it came to exist so the
// SSO sync and the admin API never clobber each other: only the IdP owns sso memberships, only an
// admin owns manual ones.
const (
	// MembershipSourceManual is an admin-added membership. It is the default for existing rows and
	// the only source an admin may hand-remove.
	MembershipSourceManual = "manual"
	// MembershipSourceSSO is a membership materialized from an SSO IdP group via an SSOGroupMapping.
	// It is reconciled (added/removed) at login and cannot be hand-removed by an admin.
	MembershipSourceSSO = "sso"
)

// UserGroupMembership joins a CCF user to a native UserGroup. The (UserID, GroupID) pair is
// unique so a user appears in a group at most once. It is a hard-delete join table (removing
// a member deletes the row); the group and the user themselves are soft-deletable.
type UserGroupMembership struct {
	UUIDModel

	CreatedAt time.Time `json:"createdAt"`

	UserID  string `json:"userId" gorm:"not null;uniqueIndex:idx_ccf_user_groups_user_group,priority:1"`
	GroupID string `json:"groupId" gorm:"not null;uniqueIndex:idx_ccf_user_groups_user_group,priority:2;index"`

	// Source records who owns this membership: MembershipSourceManual (an admin added it) or
	// MembershipSourceSSO (the login sync materialized it from an IdP group). It defaults to
	// manual so pre-BCH-1331 rows are treated as admin-managed. The SSO sync only ever touches
	// sso rows; the admin remove-member API refuses to delete sso rows (BCH-1331).
	Source string `json:"source" gorm:"not null;default:manual"`

	// Provider attributes an sso membership to the SSO provider whose mapping materialized it
	// (matching SSOUserLink.Provider / the login callback's provider name); empty for manual rows and
	// for sso rows created before attribution existed. Reconcile uses it to de-provision exactly the
	// rows the logging-in provider granted, so a group_mapping change is treated like the IdP
	// changing the user's groups, and two providers that map the SAME native group do not pin each
	// other's memberships — the previous group-scoped reconcile could not tell whose membership a
	// shared group was, leaving a renamed mapping's old membership stranded as an un-removable sso row.
	Provider string `json:"provider,omitempty" gorm:"default:''"`

	Group UserGroup `json:"group,omitempty" gorm:"foreignKey:GroupID;references:ID"`
}

func (UserGroupMembership) TableName() string {
	return "ccf_user_groups"
}

// SSOGroupMapping unifies an external IdP group with a native UserGroup. At login the SSO sync
// translates the user's IdP groups through these (Provider, ExternalGroup) rows and materializes
// the mapped native group as a source=sso membership (BCH-1331); authorization then reads only
// those native memberships. Unmapped IdP groups are intentionally dropped — they never become
// memberships and never reach subject.groups.
type SSOGroupMapping struct {
	UUIDModel

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Provider      string `json:"provider" gorm:"not null;uniqueIndex:idx_ccf_sso_group_mappings_provider_group,priority:1"`
	ExternalGroup string `json:"externalGroup" gorm:"not null;uniqueIndex:idx_ccf_sso_group_mappings_provider_group,priority:2"`
	GroupID       string `json:"groupId" gorm:"not null;index"`

	// Source records who owns the mapping: MappingSourceConfig (declared in a provider's
	// group_mapping and reconciled by boot provisioning) or MappingSourceManual (added at runtime via
	// the admin API). It defaults to config so pre-attribution rows — all of which came from config
	// provisioning — are reconciled declaratively: provisioning prunes config rows the config no
	// longer declares, while manual rows are never auto-removed.
	Source string `json:"source" gorm:"not null;default:config"`

	Group UserGroup `json:"group,omitempty" gorm:"foreignKey:GroupID;references:ID"`
}

func (SSOGroupMapping) TableName() string {
	return "ccf_sso_group_mappings"
}

// SSO group-mapping source discriminators (see SSOGroupMapping.Source).
const (
	// MappingSourceConfig is a mapping declared in a provider's group_mapping. Boot provisioning owns
	// it: it is created/re-pointed to match config and pruned when config drops it.
	MappingSourceConfig = "config"
	// MappingSourceManual is a mapping added at runtime via the admin API. Provisioning never prunes it.
	MappingSourceManual = "manual"
)

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
