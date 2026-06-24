package providers

import "fmt"

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
