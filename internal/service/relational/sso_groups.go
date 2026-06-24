package relational

import (
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
// For each listed native name it creates the UserGroup if absent, then upserts one SSOGroupMapping
// row keyed by (provider, externalGroup=claim) pointing at that group. It is idempotent and safe to
// run on every boot. It only creates/updates — it never deletes mappings, so mappings an admin added
// via the API for the same provider are left intact.
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
		for rawExternal, nativeNames := range mapping {
			external := strings.TrimSpace(rawExternal)
			if external == "" {
				continue
			}

			for _, rawName := range nativeNames {
				name := strings.TrimSpace(rawName)
				if name == "" {
					continue
				}

				// Find-or-create the native group by name (live rows only; the index is partial).
				group := UserGroup{Name: name}
				if err := tx.Where("name = ?", name).FirstOrCreate(&group).Error; err != nil {
					return err
				}
				if group.ID == nil {
					continue
				}

				row := SSOGroupMapping{Provider: provider, ExternalGroup: external, GroupID: group.ID.String()}
				// Upsert on the (provider, external_group) unique index: a re-point of an existing
				// mapping updates its group_id rather than failing or duplicating.
				if err := tx.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "provider"}, {Name: "external_group"}},
					DoUpdates: clause.AssignmentColumns([]string{"group_id"}),
				}).Create(&row).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ReconcileSSOGroupMemberships makes a user's source=sso native memberships for THIS provider
// exactly match the native groups implied by idpGroups (BCH-1331). It translates each IdP group
// through the provider's SSOGroupMapping rows, upserts a source=sso membership for every mapped
// group the user currently has, and removes the source=sso memberships for groups THIS provider
// governs that the user has lost at the IdP (login-time de-provisioning). Unmapped IdP groups are
// ignored. source=manual memberships are never read or written here, so an admin's hand-assignment
// survives even when it names the same group.
//
// De-provisioning is scoped to the set of native groups this provider maps to: a user linked to
// two IdPs (resolved to one CCF user by email) keeps the other provider's sso memberships when
// logging in here, instead of having them wiped until the next login via that provider. Residual
// ambiguity only arises if two providers map to the *same* native group, which self-heals on the
// next login via the other provider. (UserGroupMembership carries no provider attribution, so this
// group-scoped approach is the complete fix short of adding one.)
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
		// external(lower) -> native group id, and the set of native groups this provider governs.
		var mappings []SSOGroupMapping
		if err := tx.Where("provider = ?", provider).Find(&mappings).Error; err != nil {
			return err
		}
		mapByExternal := make(map[string]string, len(mappings))
		managed := make(map[string]struct{}, len(mappings)) // native group ids this provider maps to
		for _, m := range mappings {
			groupID := strings.TrimSpace(m.GroupID)
			key := strings.ToLower(strings.TrimSpace(m.ExternalGroup))
			if key != "" && groupID != "" {
				mapByExternal[key] = groupID
				managed[groupID] = struct{}{}
			}
		}

		// desired = the native group ids the user's current IdP groups map to.
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
		var toRemove []string
		for _, m := range existing {
			have[m.GroupID] = struct{}{}
			// Only de-provision groups THIS provider governs; another IdP's memberships are left
			// alone (they have no mapping here, so they are absent from `managed`).
			if _, governed := managed[m.GroupID]; !governed {
				continue
			}
			if _, ok := desired[m.GroupID]; !ok {
				toRemove = append(toRemove, m.GroupID)
			}
		}

		for groupID := range desired {
			if _, ok := have[groupID]; ok {
				continue
			}
			row := UserGroupMembership{UserID: userID, GroupID: groupID, Source: MembershipSourceSSO}
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
		}
		return nil
	})
}
