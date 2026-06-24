package relational

import (
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ProvisionSSOGroupMappings declaratively reconciles one SSO provider's config-declared group
// mappings into the database (BCH-1331). mapping is keyed by native CCF group name and lists the
// external IdP group claims that map into it:
//
//	security-team:        // native UserGroup.Name
//	  - eng-security      // IdP group claims
//	  - sec-ops
//
// For each native group it creates the UserGroup if absent, then upserts one SSOGroupMapping row
// per (provider, externalGroup) pair pointing at that group. It is idempotent and safe to run on
// every boot. It only creates/updates — it never deletes mappings, so mappings an admin added via
// the API for the same provider are left intact.
func ProvisionSSOGroupMappings(db *gorm.DB, provider string, mapping map[string][]string) error {
	provider = strings.TrimSpace(provider)
	if provider == "" || len(mapping) == 0 {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		for rawName, externals := range mapping {
			name := strings.TrimSpace(rawName)
			if name == "" {
				continue
			}

			// Find-or-create the native group by name (live rows only; the unique index is partial).
			group := UserGroup{Name: name}
			if err := tx.Where("name = ?", name).FirstOrCreate(&group).Error; err != nil {
				return err
			}
			if group.ID == nil {
				continue
			}
			groupID := group.ID.String()

			for _, rawExternal := range externals {
				external := strings.TrimSpace(rawExternal)
				if external == "" {
					continue
				}
				row := SSOGroupMapping{Provider: provider, ExternalGroup: external, GroupID: groupID}
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

// ReconcileSSOGroupMemberships makes a user's source=sso native memberships exactly match the
// native groups implied by idpGroups for the given provider (BCH-1331). It translates each IdP
// group through the provider's SSOGroupMapping rows, upserts a source=sso membership for every
// mapped group the user currently has, and removes the source=sso memberships for mapped groups
// the user has lost at the IdP (login-time de-provisioning). Unmapped IdP groups are ignored.
// source=manual memberships are never read or written here, so an admin's hand-assignment is
// untouched even when it names the same group.
func ReconcileSSOGroupMemberships(db *gorm.DB, userID, provider string, idpGroups []string) error {
	userID = strings.TrimSpace(userID)
	provider = strings.TrimSpace(provider)
	if userID == "" || provider == "" {
		return nil
	}

	// external(lower) -> native group id, for this provider.
	var mappings []SSOGroupMapping
	if err := db.Where("provider = ?", provider).Find(&mappings).Error; err != nil {
		return err
	}
	mapByExternal := make(map[string]string, len(mappings))
	for _, m := range mappings {
		key := strings.ToLower(strings.TrimSpace(m.ExternalGroup))
		if key != "" && strings.TrimSpace(m.GroupID) != "" {
			mapByExternal[key] = m.GroupID
		}
	}

	// desired = the set of native group ids the user's current IdP groups map to.
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

	// existing = the user's current source=sso memberships.
	var existing []UserGroupMembership
	if err := db.Where("user_id = ? AND source = ?", userID, MembershipSourceSSO).
		Find(&existing).Error; err != nil {
		return err
	}
	have := make(map[string]struct{}, len(existing))
	var toRemove []string
	for _, m := range existing {
		have[m.GroupID] = struct{}{}
		if _, ok := desired[m.GroupID]; !ok {
			toRemove = append(toRemove, m.GroupID)
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
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
