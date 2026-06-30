package providers

import (
	"fmt"
	"strings"
)

// buildClaimGroups creates claim-based group keys from user claims
// For example: "hd:example.com", "email:user@example.com", "groups:admin"
func buildClaimGroups(claims map[string]interface{}) map[string]struct{} {
	groups := make(map[string]struct{})

	for key, value := range claims {
		// Skip standard OIDC/OAuth claims
		if key == "iss" || key == "aud" || key == "exp" || key == "iat" || key == "sub" {
			continue
		}

		switch v := value.(type) {
		case string:
			groups[fmt.Sprintf("%s:%s", key, v)] = struct{}{}
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					groups[fmt.Sprintf("%s:%s", key, str)] = struct{}{}
				}
			}
		}
	}

	return groups
}

// claimGroupKeys returns the raw claim-group identifiers (e.g. "groups:admin", "hd:example.com")
// derived from a user's claims. These are the exact keys an admin maps via group_mapping /
// SSOGroupMapping, and they are carried on UserInfo.RawGroups for the login sync to translate
// through the DB (BCH-1331). Unmapped keys are harmless — reconcile simply ignores them.
func claimGroupKeys(claims map[string]interface{}) []string {
	cg := buildClaimGroups(claims)
	keys := make([]string, 0, len(cg))
	for k := range cg {
		keys = append(keys, k)
	}
	return keys
}

// mapClaimGroups translates a user's claim-group identifiers through the provider's configured
// group_mapping and returns the native CCF group name(s) those claims grant.
//
// Matching is CASE-INSENSITIVE, and deliberately so: viper lowercases every group_mapping key when
// it loads sso.yaml (see config.LoadSSOConfig), whereas the claim values come straight from the IdP
// with their original casing — an Active Directory group is typically something like
// "rAppMyGroup". A case-sensitive lookup therefore silently drops every mapping whose IdP group name
// contains an uppercase letter, so the user's groups resolve to an empty set and required-group
// gating rejects them. Folding both sides to lower case here mirrors what the DB-backed reconcile
// path already does (relational.ReconcileSSOGroupMemberships) and keeps the two translation paths in
// agreement.
func mapClaimGroups(mapping map[string][]string, claims map[string]interface{}) []string {
	if len(mapping) == 0 {
		return nil
	}

	lowered := make(map[string][]string, len(mapping))
	for key, groups := range mapping {
		lowered[strings.ToLower(strings.TrimSpace(key))] = groups
	}

	var mappedGroups []string
	for claimGroup := range buildClaimGroups(claims) {
		if groups, ok := lowered[strings.ToLower(strings.TrimSpace(claimGroup))]; ok {
			mappedGroups = append(mappedGroups, groups...)
		}
	}

	return mappedGroups
}
