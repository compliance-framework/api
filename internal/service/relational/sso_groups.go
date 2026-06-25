package relational

import (
	"errors"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ProvisionSSOGroupMappings declaratively reconciles one SSO provider's config-declared group
// mappings into the database (BCH-1331). `mapping` is the provider's group_mapping verbatim: it is
// keyed by the raw IdP claim group and lists the native CCF group name(s) that claim grants:
//
//	"groups:ccf-admins":             // raw IdP claim (SSOGroupMapping.ExternalGroup)
//	  - ccf-admins                   // native UserGroup.Name
//	"hd:example.com":
//	  - ccf-authorized-users
//
// For each listed native name it creates the UserGroup if absent, then upserts one source=config
// SSOGroupMapping row keyed by (provider, externalGroup=claim) pointing at that group, and finally
// PRUNES this provider's source=config rows the config no longer declares (a removed group_mapping
// entry). Mappings an admin added at runtime (source=manual) are never pruned. It is idempotent and
// safe to run on every boot; pruning a mapping is what lets the now-unreferenced group be reclaimed
// by CleanupOrphanedSSOGroups.
//
// Caveat: the (provider, external_group) unique index means one IdP claim maps to exactly one native
// group. If a claim lists multiple native names, the last one wins (each overwrites the prior row's
// group_id). Real configs are 1:1; list a native group under several distinct claims instead.
func ProvisionSSOGroupMappings(db *gorm.DB, provider string, mapping map[string][]string) error {
	provider = strings.TrimSpace(provider)
	if provider == "" || len(mapping) == 0 {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// External claim keys the config declares for this provider — the keep-set for the prune.
		configExternals := make([]string, 0, len(mapping))
		seen := make(map[string]struct{}, len(mapping))
		for rawExternal, nativeNames := range mapping {
			external := strings.TrimSpace(rawExternal)
			if external == "" {
				continue
			}
			if _, ok := seen[external]; !ok {
				seen[external] = struct{}{}
				configExternals = append(configExternals, external)
			}

			for _, rawName := range nativeNames {
				name := strings.TrimSpace(rawName)
				if name == "" {
					continue
				}

				// Find-or-create the native group by name (live rows only; the index is partial).
				// Attrs applies Source only on the CREATE path, so a group an admin already created
				// keeps its manual source (and its protection from cleanup) even if SSO config later
				// names it.
				group := UserGroup{Name: name}
				if err := tx.Where("name = ?", name).
					Attrs(UserGroup{Source: GroupSourceSSO}).
					FirstOrCreate(&group).Error; err != nil {
					return err
				}
				if group.ID == nil {
					continue
				}

				row := SSOGroupMapping{
					Provider: provider, ExternalGroup: external,
					GroupID: group.ID.String(), Source: MappingSourceConfig,
				}
				// Upsert on the (provider, external_group) unique index: a re-point updates the
				// group_id and re-affirms config ownership rather than failing or duplicating.
				if err := tx.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "provider"}, {Name: "external_group"}},
					DoUpdates: clause.AssignmentColumns([]string{"group_id", "source"}),
				}).Create(&row).Error; err != nil {
					return err
				}
			}
		}

		// Prune this provider's config-sourced mappings that the config no longer declares. Manual
		// (admin-API) mappings are left intact.
		del := tx.Where("provider = ? AND source = ?", provider, MappingSourceConfig)
		if len(configExternals) > 0 {
			del = del.Where("external_group NOT IN ?", configExternals)
		}
		if err := del.Delete(&SSOGroupMapping{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// CleanupOrphanedSSOGroups soft-deletes native groups that SSO provisioning created (Source=sso) and
// that nothing references anymore: no SSOGroupMapping points at them, no user is a member, and no
// role assignment grants by their name. This is what reclaims a group left behind when a provider's
// group_mapping value is renamed or removed (e.g. "ccf-authorized-uzers" after a typo'd rename) — the
// mapping re-points to the new group and the old one becomes an unreferenced orphan.
//
// It is the boot-time SWEEP over every sso group. The per-login de-provision path also cleans up
// (see ReconcileSSOGroupMemberships → pruneOrphanedSSOGroups), which is what catches a group that
// only becomes empty when the last member is removed at login — too late for the preceding boot.
//
// It is deliberately conservative:
//   - Source=manual groups (admin-created, and all pre-attribution rows) are never touched.
//   - A group with any member, mapping, or group role assignment is kept — the same emptiness guard
//     the admin DeleteGroup API enforces, so a group still in use is never silently removed.
//
// Run it AFTER provisioning every provider so a group mapped by one provider is not deleted while
// another provider's mappings are still being applied.
func CleanupOrphanedSSOGroups(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var ids []string
		if err := tx.Model(&UserGroup{}).Where("source = ?", GroupSourceSSO).
			Pluck("id", &ids).Error; err != nil {
			return err
		}
		return pruneOrphanedSSOGroups(tx, ids)
	})
}

// pruneOrphanedSSOGroups soft-deletes, among the given group ids, the ones that are Source=sso and
// now fully unreferenced (no SSOGroupMapping, no members, no group role assignment). It is the shared
// guard used by both the boot sweep and the login de-provision path, and runs in the caller's
// transaction. Non-sso, still-referenced, or already-deleted ids are skipped.
func pruneOrphanedSSOGroups(tx *gorm.DB, groupIDs []string) error {
	for _, groupID := range groupIDs {
		groupID = strings.TrimSpace(groupID)
		if groupID == "" {
			continue
		}

		// Must be a live sso group; anything else (manual, or already gone) is left alone.
		var group UserGroup
		if err := tx.Where("id = ? AND source = ?", groupID, GroupSourceSSO).
			First(&group).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return err
		}

		var mappingCount int64
		if err := tx.Model(&SSOGroupMapping{}).Where("group_id = ?", groupID).
			Count(&mappingCount).Error; err != nil {
			return err
		}
		if mappingCount > 0 {
			continue // still mapped by some provider
		}

		var memberCount int64
		if err := tx.Model(&UserGroupMembership{}).Where("group_id = ?", groupID).
			Count(&memberCount).Error; err != nil {
			return err
		}
		if memberCount > 0 {
			continue // still has members (sso or manual)
		}

		var grantCount int64
		if err := tx.Model(&CCFRoleAssignment{}).
			Where("assignee_type = ? AND assignee_id = ?",
				RoleAssigneeTypeGroup, NormalizeAssigneeID(group.Name)).
			Count(&grantCount).Error; err != nil {
			return err
		}
		if grantCount > 0 {
			continue // a role assignment (config or admin) still grants by this group's name
		}

		if err := tx.Delete(&UserGroup{}, "id = ?", groupID).Error; err != nil {
			return err
		}
	}
	return nil
}

// ReconcileSSOGroupMemberships makes the user's sso native memberships attributed to THIS provider
// exactly match the native groups implied by idpGroups (BCH-1331). It translates each IdP group
// through the provider's SSOGroupMapping rows, then materializes a source=sso membership (attributed
// to this provider) for every mapped group the user currently presents and DELETES the memberships
// this provider granted that the user no longer has. Unmapped IdP groups are ignored. source=manual
// memberships are never read or written here, so an admin's hand-assignment survives even when it
// names the same group.
//
// A group_mapping change is therefore treated exactly like the IdP changing the user's groups: if a
// provider's mapping is removed or re-pointed (e.g. a value renamed from "ccf-authorized-users" to
// "ccf-authorized-uzers"), that provider stops granting the old group, so on the next login the old
// membership is removed and the new one added — there is no lingering, un-removable row.
//
// Attribution by provider is what makes this correct when two providers map the SAME native group
// (the default config has google AND github both mapping "ccf-authorized-users"): the membership
// records which provider granted it, so renaming GOOGLE's mapping removes google's membership even
// though github still maps that group. A user genuinely entitled via github re-acquires it on their
// next github login. Memberships owned by a DIFFERENT provider are left for that provider to
// reconcile; an unattributed pre-attribution row is treated as the logging-in provider's (so the
// historical stuck rows self-heal). The row is adopted to the current provider whenever this
// provider grants the group, keeping ownership current. (user_id, group_id) stays unique: a group
// has at most one membership row, whose Provider reflects its most recent grantor.
//
// All reads and writes run inside a single transaction so concurrent logins for the same user
// reconcile atomically.
func ReconcileSSOGroupMemberships(db *gorm.DB, userID, provider string, idpGroups []string) error {
	userID = strings.TrimSpace(userID)
	provider = strings.TrimSpace(provider)
	if userID == "" || provider == "" {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// external(lower) -> native group id for this provider's mappings.
		var mappings []SSOGroupMapping
		if err := tx.Where("provider = ?", provider).Find(&mappings).Error; err != nil {
			return err
		}
		mapByExternal := make(map[string]string, len(mappings))
		for _, m := range mappings {
			groupID := strings.TrimSpace(m.GroupID)
			key := strings.ToLower(strings.TrimSpace(m.ExternalGroup))
			if key != "" && groupID != "" {
				mapByExternal[key] = groupID
			}
		}

		// desired = the native group ids the user's current IdP groups map to under this provider.
		desired := make(map[string]struct{}, len(idpGroups))
		for _, g := range idpGroups {
			key := strings.ToLower(strings.TrimSpace(g))
			if key == "" {
				continue
			}
			if groupID, ok := mapByExternal[key]; ok {
				desired[groupID] = struct{}{}
			}
		}

		// existing = the user's current source=sso memberships (across all providers).
		var existing []UserGroupMembership
		if err := tx.Where("user_id = ? AND source = ?", userID, MembershipSourceSSO).
			Find(&existing).Error; err != nil {
			return err
		}
		have := make(map[string]struct{}, len(existing))
		var toRemove []string // delete: owned by this provider but no longer granted
		var toAdopt []string  // (re)claim ownership: this provider grants it but the row names another
		for _, m := range existing {
			have[m.GroupID] = struct{}{}
			if _, want := desired[m.GroupID]; want {
				// This provider grants the group now: keep it and make sure the row is attributed
				// here (adopt another provider's row or a pre-attribution one).
				if strings.TrimSpace(m.Provider) != provider {
					toAdopt = append(toAdopt, m.GroupID)
				}
				continue
			}
			// Not granted now. Only de-provision rows this provider owns (or unattributed legacy
			// rows); a different provider's membership is left for that provider to reconcile.
			if rowProvider := strings.TrimSpace(m.Provider); rowProvider != "" && rowProvider != provider {
				continue
			}
			toRemove = append(toRemove, m.GroupID)
		}

		for groupID := range desired {
			if _, ok := have[groupID]; ok {
				continue
			}
			row := UserGroupMembership{
				UserID: userID, GroupID: groupID, Source: MembershipSourceSSO, Provider: provider,
			}
			// DoNothing on the (user_id, group_id) unique index: if a manual membership already
			// covers this group the user is in it either way, and we must not flip its source.
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "user_id"}, {Name: "group_id"}},
				DoNothing: true,
			}).Create(&row).Error; err != nil {
				return err
			}
		}
		if len(toRemove) > 0 {
			if err := tx.Where("user_id = ? AND source = ? AND group_id IN ?",
				userID, MembershipSourceSSO, toRemove).
				Delete(&UserGroupMembership{}).Error; err != nil {
				return err
			}
			// Removing this user may have emptied a now-unmapped sso group (e.g. the old group after
			// a group_mapping change): reclaim it here, at the moment it becomes orphaned, rather
			// than waiting for the next boot sweep.
			if err := pruneOrphanedSSOGroups(tx, toRemove); err != nil {
				return err
			}
		}
		if len(toAdopt) > 0 {
			// Scoped to sso rows so a manual membership for the same group is never touched.
			if err := tx.Model(&UserGroupMembership{}).
				Where("user_id = ? AND source = ? AND group_id IN ?",
					userID, MembershipSourceSSO, toAdopt).
				Update("provider", provider).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
