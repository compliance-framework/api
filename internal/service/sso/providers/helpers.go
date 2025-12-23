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
