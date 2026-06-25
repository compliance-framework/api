package relational

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupGroupsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&User{}, &UserGroup{}, &UserGroupMembership{}, &SSOGroupMapping{}, &CCFRoleAssignment{},
	))
	return db
}

func createGroupsUser(t *testing.T, db *gorm.DB) string {
	t.Helper()
	user := User{Email: "u@example.com", FirstName: "U", LastName: "Ser"}
	require.NoError(t, db.Create(&user).Error)
	return user.ID.String()
}

// ssoMembershipGroupIDs returns the group ids the user belongs to via source=sso memberships.
func ssoMembershipGroupIDs(t *testing.T, db *gorm.DB, userID string) []string {
	t.Helper()
	var ids []string
	require.NoError(t, db.Model(&UserGroupMembership{}).
		Where("user_id = ? AND source = ?", userID, MembershipSourceSSO).
		Pluck("group_id", &ids).Error)
	sort.Strings(ids)
	return ids
}

// TestProvisionSSOGroupMappingsCreatesGroupsAndMappings proves config provisioning creates a native
// group named after each mapped VALUE (not the IdP-claim key) and one mapping row per (provider,
// externalGroup=claim) pair, and is idempotent across repeated boots.
func TestProvisionSSOGroupMappingsCreatesGroupsAndMappings(t *testing.T) {
	db := setupGroupsDB(t)
	// Keyed by raw IdP claim; the value is the native CCF group name to create.
	mapping := map[string][]string{
		"groups:ccf-admins": {"security-team"},
		"hd:example.com":    {"authorized-users"},
	}

	require.NoError(t, ProvisionSSOGroupMappings(db, "okta", mapping))
	// Re-running must not duplicate anything.
	require.NoError(t, ProvisionSSOGroupMappings(db, "okta", mapping))

	// Native groups carry the mapped VALUE name, never the claim key.
	for _, name := range []string{"security-team", "authorized-users"} {
		var groups []UserGroup
		require.NoError(t, db.Where("name = ?", name).Find(&groups).Error)
		require.Len(t, groups, 1, "expected exactly one native group %q", name)
	}
	var claimNamed int64
	require.NoError(t, db.Model(&UserGroup{}).
		Where("name IN ?", []string{"groups:ccf-admins", "hd:example.com"}).Count(&claimNamed).Error)
	require.Zero(t, claimNamed, "native groups must not be named after IdP claims")

	// One mapping row per claim, each pointing at its native group.
	var mappings []SSOGroupMapping
	require.NoError(t, db.Where("provider = ?", "okta").Find(&mappings).Error)
	require.Len(t, mappings, 2)
	secID := groupIDByName(t, db, "security-team")
	for _, m := range mappings {
		switch m.ExternalGroup {
		case "groups:ccf-admins":
			require.Equal(t, secID, m.GroupID)
		case "hd:example.com":
			require.Equal(t, groupIDByName(t, db, "authorized-users"), m.GroupID)
		default:
			t.Fatalf("unexpected external group %q", m.ExternalGroup)
		}
	}
}

// TestProvisionSSOGroupMappingsRepointsExisting proves re-running with the same IdP claim pointed at
// a different native group updates the existing row's group_id rather than failing or duplicating.
func TestProvisionSSOGroupMappingsRepointsExisting(t *testing.T) {
	db := setupGroupsDB(t)
	require.NoError(t, ProvisionSSOGroupMappings(db, "okta", map[string][]string{"groups:eng": {"team-a"}}))
	require.NoError(t, ProvisionSSOGroupMappings(db, "okta", map[string][]string{"groups:eng": {"team-b"}}))

	var teamB UserGroup
	require.NoError(t, db.Where("name = ?", "team-b").First(&teamB).Error)

	var mappings []SSOGroupMapping
	require.NoError(t, db.Where("provider = ? AND external_group = ?", "okta", "groups:eng").Find(&mappings).Error)
	require.Len(t, mappings, 1)
	require.Equal(t, teamB.ID.String(), mappings[0].GroupID)
}

// TestReconcileSSOGroupMembershipsAddsAndRemoves proves login reconcile materializes mapped IdP
// groups as source=sso memberships and de-provisions ones the user has lost at the IdP.
func TestReconcileSSOGroupMembershipsAddsAndRemoves(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)
	// Keyed by raw IdP claim -> native CCF group name.
	require.NoError(t, ProvisionSSOGroupMappings(db, "okta", map[string][]string{
		"idp:eng-security": {"security"},
		"idp:audit":        {"auditors"},
	}))
	secID := groupIDByName(t, db, "security")
	audID := groupIDByName(t, db, "auditors")

	// First login: user has both raw IdP claim groups.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", []string{"idp:eng-security", "idp:audit"}))
	require.Equal(t, sortedPair(secID, audID), ssoMembershipGroupIDs(t, db, userID))

	// Second login: user lost "idp:audit" at the IdP -> that membership is de-provisioned.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", []string{"idp:eng-security"}))
	require.Equal(t, []string{secID}, ssoMembershipGroupIDs(t, db, userID))

	// Unmapped IdP claim groups never create memberships.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", []string{"idp:eng-security", "random"}))
	require.Equal(t, []string{secID}, ssoMembershipGroupIDs(t, db, userID))
}

// TestReconcileSSOGroupMembershipsLeavesManualUntouched proves the SSO sync never removes or
// rewrites a source=manual membership, even when it names the same group an IdP group maps to.
func TestReconcileSSOGroupMembershipsLeavesManualUntouched(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)
	require.NoError(t, ProvisionSSOGroupMappings(db, "okta", map[string][]string{"idp:eng-security": {"security"}}))
	secID := groupIDByName(t, db, "security")

	// Admin hand-adds the user to a separate manual-only group.
	manualGroup := UserGroup{Name: "manual-only"}
	require.NoError(t, db.Create(&manualGroup).Error)
	require.NoError(t, db.Create(&UserGroupMembership{
		UserID: userID, GroupID: manualGroup.ID.String(), Source: MembershipSourceManual,
	}).Error)

	// Reconcile with an IdP claim group; then reconcile it away.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", []string{"idp:eng-security"}))
	require.Equal(t, []string{secID}, ssoMembershipGroupIDs(t, db, userID))
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", nil))
	require.Empty(t, ssoMembershipGroupIDs(t, db, userID))

	// The manual membership survives every reconcile.
	var manualCount int64
	require.NoError(t, db.Model(&UserGroupMembership{}).
		Where("user_id = ? AND source = ?", userID, MembershipSourceManual).
		Count(&manualCount).Error)
	require.Equal(t, int64(1), manualCount)
}

// TestReconcileSSOGroupMembershipsIsProviderScoped proves that reconciling one provider's groups
// does not de-provision a different provider's sso memberships for the same user (a user linked to
// two IdPs by email). Only the groups the logging-in provider governs are reconciled.
func TestReconcileSSOGroupMembershipsIsProviderScoped(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)
	require.NoError(t, ProvisionSSOGroupMappings(db, "okta", map[string][]string{"idp:eng-security": {"security"}}))
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"idp:data-eng": {"data"}}))
	secID := groupIDByName(t, db, "security")
	dataID := groupIDByName(t, db, "data")

	// Login via okta grants "security"; login via google grants "data".
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", []string{"idp:eng-security"}))
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"idp:data-eng"}))
	require.Equal(t, sortedPair(secID, dataID), ssoMembershipGroupIDs(t, db, userID))

	// A subsequent okta login (still has idp:eng-security) must NOT wipe the google-granted "data".
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", []string{"idp:eng-security"}))
	require.Equal(t, sortedPair(secID, dataID), ssoMembershipGroupIDs(t, db, userID))

	// Losing idp:eng-security at okta de-provisions only "security"; "data" survives.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "okta", nil))
	require.Equal(t, []string{dataID}, ssoMembershipGroupIDs(t, db, userID))
}

// membershipSource returns the source of the user's membership in the given group, or "" if none.
func membershipSource(t *testing.T, db *gorm.DB, userID, groupID string) string {
	t.Helper()
	var sources []string
	require.NoError(t, db.Model(&UserGroupMembership{}).
		Where("user_id = ? AND group_id = ?", userID, groupID).
		Pluck("source", &sources).Error)
	if len(sources) == 0 {
		return ""
	}
	return sources[0]
}

// TestReconcileSSOGroupMembershipsRemovesAfterRename proves a group_mapping value rename behaves like
// the IdP changing the user's groups: the claim key stays the same but maps to a new native group, so
// the next login removes the old membership and adds the new one — no lingering row.
func TestReconcileSSOGroupMembershipsRemovesAfterRename(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)

	// Original config: claim "hd:example.com" grants native group "authorized-users".
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{
		"hd:example.com": {"authorized-users"},
	}))
	oldID := groupIDByName(t, db, "authorized-users")

	// User logs in and is materialized into the old group.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:example.com"}))
	require.Equal(t, []string{oldID}, ssoMembershipGroupIDs(t, db, userID))

	// Config value renamed; the claim key is unchanged so the mapping row re-points at the new group.
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{
		"hd:example.com": {"authorized-uzers"},
	}))
	newID := groupIDByName(t, db, "authorized-uzers")

	// Next login: only the new group remains; the old membership is gone entirely (not stale).
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:example.com"}))
	require.Equal(t, []string{newID}, ssoMembershipGroupIDs(t, db, userID))
	require.Equal(t, "", membershipSource(t, db, userID, oldID), "old membership must be deleted")
}

// TestReconcileSSOGroupMembershipsRemovesAfterRenameDespiteOtherProvider reproduces the reported
// production bug exactly (gustavo@container-solutions.com, a Google user): the default config has TWO
// providers (google + github) mapping the SAME native group ("ccf-authorized-users"). Renaming only
// google's value must still REMOVE google's membership — the previous group-scoped reconcile left it
// pinned because github kept the group "mapped", stranding the user in BOTH groups as un-removable
// sso rows. Provider attribution fixes it: the membership is google's, and google no longer grants it.
func TestReconcileSSOGroupMembershipsRemovesAfterRenameDespiteOtherProvider(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)
	// Both providers map the same native group, like sso.yaml's google + github.
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"authorized-users"}}))
	require.NoError(t, ProvisionSSOGroupMappings(db, "github", map[string][]string{"gh:org": {"authorized-users"}}))
	authID := groupIDByName(t, db, "authorized-users")

	// User logs in via google only and is materialized into the shared group (attributed to google).
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))
	require.Equal(t, []string{authID}, ssoMembershipGroupIDs(t, db, userID))

	// Google's value is renamed; github STILL maps "authorized-users".
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"authorized-uzers"}}))
	uzersID := groupIDByName(t, db, "authorized-uzers")

	// Google re-login: the old group is removed despite github still mapping it (the membership was
	// google's), and the new group becomes the only sso membership.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))
	require.Equal(t, []string{uzersID}, ssoMembershipGroupIDs(t, db, userID))
	require.Equal(t, "", membershipSource(t, db, userID, authID), "google's old membership must be deleted")

	// A github login (the user IS in the github org) re-grants the shared group via github.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "github", []string{"gh:org"}))
	require.Equal(t, MembershipSourceSSO, membershipSource(t, db, userID, authID))
}

// TestReconcileSSOGroupMembershipsAdoptsLegacyUnattributedRow proves a pre-attribution sso row
// (Provider == "") is treated as the logging-in provider's: it is adopted when still granted, and —
// crucially for the stuck rows already in the DB — removed when that provider's mapping renames away.
func TestReconcileSSOGroupMembershipsAdoptsLegacyUnattributedRow(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"authorized-users"}}))
	authID := groupIDByName(t, db, "authorized-users")

	// Simulate a row created before provider attribution existed: source=sso, provider empty.
	require.NoError(t, db.Create(&UserGroupMembership{
		UserID: userID, GroupID: authID, Source: MembershipSourceSSO, Provider: "",
	}).Error)

	// A login that still grants the group adopts the row to the provider.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))
	var adopted UserGroupMembership
	require.NoError(t, db.Where("user_id = ? AND group_id = ?", userID, authID).First(&adopted).Error)
	require.Equal(t, "google", adopted.Provider)

	// Rename google's mapping; the (now-attributed) row is removed on the next login.
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"authorized-uzers"}}))
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))
	require.Equal(t, "", membershipSource(t, db, userID, authID))
}

// groupExists reports whether a live (not soft-deleted) group with the given name exists.
func groupExists(t *testing.T, db *gorm.DB, name string) bool {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(&UserGroup{}).Where("name = ?", name).Count(&count).Error)
	return count > 0
}

// TestProvisionMarksCreatedGroupsSSO proves provisioning tags groups it creates as Source=sso, while
// a pre-existing admin (manual) group keeps its source even when SSO config later names it.
func TestProvisionMarksCreatedGroupsSSO(t *testing.T) {
	db := setupGroupsDB(t)

	// An admin-created group that SSO config will also reference.
	require.NoError(t, db.Create(&UserGroup{Name: "shared", Source: GroupSourceManual}).Error)

	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{
		"hd:cs":  {"sso-made"},
		"gh:org": {"shared"},
	}))

	var ssoMade, shared UserGroup
	require.NoError(t, db.Where("name = ?", "sso-made").First(&ssoMade).Error)
	require.Equal(t, GroupSourceSSO, ssoMade.Source)
	require.NoError(t, db.Where("name = ?", "shared").First(&shared).Error)
	require.Equal(t, GroupSourceManual, shared.Source, "admin group must keep manual source")
}

// TestReconcileCleansUpOrphanedGroupAtLogin proves the old sso group is reclaimed AT LOGIN, the
// moment reconcile removes the user's last membership — the exact flow the user described: change the
// map, user logs in, gets the new group, loses the old, and the now-empty unmapped old group is gone.
func TestReconcileCleansUpOrphanedGroupAtLogin(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)

	// Boot-equivalent: provision maps the claim to the old group; user logs in and joins it.
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"old-group"}}))
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))
	oldID := groupIDByName(t, db, "old-group")
	require.Equal(t, []string{oldID}, ssoMembershipGroupIDs(t, db, userID))

	// Admin changes the map: same claim now grants a different group. (Provisioning re-points the
	// mapping and prunes nothing here since the claim key is unchanged.)
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"new-group"}}))
	require.True(t, groupExists(t, db, "old-group"), "old group still present before the user re-logs in")

	// User logs in again: joins new-group, leaves old-group, and old-group (empty, unmapped, roleless)
	// is cleaned up right here at login.
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))
	require.Equal(t, []string{groupIDByName(t, db, "new-group")}, ssoMembershipGroupIDs(t, db, userID))
	require.False(t, groupExists(t, db, "old-group"), "emptied unmapped sso group must be cleaned at login")
}

// TestReconcileKeepsRoleGrantedGroupAtLogin proves login cleanup respects the role guard: an emptied
// unmapped sso group that still has a role assignment is kept, not deleted.
func TestReconcileKeepsRoleGrantedGroupAtLogin(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"old-group"}}))
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))
	require.NoError(t, db.Create(&CCFRoleAssignment{
		RoleName: "viewer", AssigneeType: RoleAssigneeTypeGroup,
		AssigneeID: NormalizeAssigneeID("old-group"), Source: RoleAssignmentSourceManual,
	}).Error)

	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"new-group"}}))
	require.NoError(t, ReconcileSSOGroupMemberships(db, userID, "google", []string{"hd:cs"}))

	require.True(t, groupExists(t, db, "old-group"), "role-granted group must survive even when emptied")
}

// mappingExists reports whether a (provider, externalGroup) mapping row exists.
func mappingExists(t *testing.T, db *gorm.DB, provider, external string) bool {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(&SSOGroupMapping{}).
		Where("provider = ? AND external_group = ?", provider, external).Count(&count).Error)
	return count > 0
}

// TestProvisionPrunesConfigRemovedMappings proves a removed group_mapping entry's row is deleted on
// the next provisioning, while an admin-added (source=manual) mapping for the same provider survives.
// This is the case that left ccf-github-users mapped (and thus undeletable) after its config entry
// was removed.
func TestProvisionPrunesConfigRemovedMappings(t *testing.T) {
	db := setupGroupsDB(t)

	// Initial config: two github mappings.
	require.NoError(t, ProvisionSSOGroupMappings(db, "github", map[string][]string{
		"gh:org-a": {"team-a"},
		"gh:org-b": {"github-users"},
	}))
	// An admin adds a runtime mapping the config never declares.
	adminGrp := UserGroup{Name: "admin-mapped", Source: GroupSourceManual}
	require.NoError(t, db.Create(&adminGrp).Error)
	require.NoError(t, db.Create(&SSOGroupMapping{
		Provider: "github", ExternalGroup: "gh:manual", GroupID: adminGrp.ID.String(),
		Source: MappingSourceManual,
	}).Error)

	// Config now drops "gh:org-b" (the ccf-github-users analogue).
	require.NoError(t, ProvisionSSOGroupMappings(db, "github", map[string][]string{
		"gh:org-a": {"team-a"},
	}))

	require.True(t, mappingExists(t, db, "github", "gh:org-a"), "still-declared mapping kept")
	require.False(t, mappingExists(t, db, "github", "gh:org-b"), "config-removed mapping must be pruned")
	require.True(t, mappingExists(t, db, "github", "gh:manual"), "admin (manual) mapping must survive")

	// With the mapping gone, the orphaned sso group is reclaimable by cleanup.
	require.NoError(t, CleanupOrphanedSSOGroups(db))
	require.False(t, groupExists(t, db, "github-users"), "unmapped sso group must be cleaned up")
	require.True(t, groupExists(t, db, "team-a"), "still-mapped group kept")
	require.True(t, groupExists(t, db, "admin-mapped"), "admin-mapped group kept")
}

// TestCleanupOrphanedSSOGroups proves boot cleanup removes only fully-unreferenced sso groups and
// protects everything else: still-mapped groups, groups with members, groups granted a role, and
// admin (manual) groups.
func TestCleanupOrphanedSSOGroups(t *testing.T) {
	db := setupGroupsDB(t)
	userID := createGroupsUser(t, db)

	// orphan: sso-made, no mapping, no members, no grants -> deleted.
	require.NoError(t, db.Create(&UserGroup{Name: "orphan", Source: GroupSourceSSO}).Error)

	// mapped: sso-made and still has a mapping -> kept.
	require.NoError(t, ProvisionSSOGroupMappings(db, "google", map[string][]string{"hd:cs": {"mapped"}}))

	// withMember: sso-made, no mapping, but has a member -> kept.
	withMember := UserGroup{Name: "with-member", Source: GroupSourceSSO}
	require.NoError(t, db.Create(&withMember).Error)
	require.NoError(t, db.Create(&UserGroupMembership{
		UserID: userID, GroupID: withMember.ID.String(), Source: MembershipSourceManual,
	}).Error)

	// withGrant: sso-made, no mapping/members, but a role assignment grants by its name -> kept.
	require.NoError(t, db.Create(&UserGroup{Name: "with-grant", Source: GroupSourceSSO}).Error)
	require.NoError(t, db.Create(&CCFRoleAssignment{
		RoleName: "viewer", AssigneeType: RoleAssigneeTypeGroup,
		AssigneeID: NormalizeAssigneeID("with-grant"), Source: RoleAssignmentSourceConfig,
	}).Error)

	// adminOrphan: manual, unreferenced -> kept (never auto-deleted).
	require.NoError(t, db.Create(&UserGroup{Name: "admin-orphan", Source: GroupSourceManual}).Error)

	require.NoError(t, CleanupOrphanedSSOGroups(db))

	require.False(t, groupExists(t, db, "orphan"), "unreferenced sso group must be deleted")
	require.True(t, groupExists(t, db, "mapped"), "still-mapped sso group must be kept")
	require.True(t, groupExists(t, db, "with-member"), "sso group with members must be kept")
	require.True(t, groupExists(t, db, "with-grant"), "sso group granted a role must be kept")
	require.True(t, groupExists(t, db, "admin-orphan"), "manual group must never be auto-deleted")
}

func groupIDByName(t *testing.T, db *gorm.DB, name string) string {
	t.Helper()
	var g UserGroup
	require.NoError(t, db.Where("name = ?", name).First(&g).Error)
	return g.ID.String()
}

func sortedPair(a, b string) []string {
	out := []string{a, b}
	sort.Strings(out)
	return out
}
