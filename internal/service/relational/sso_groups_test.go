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
		&User{}, &UserGroup{}, &UserGroupMembership{}, &SSOGroupMapping{},
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
