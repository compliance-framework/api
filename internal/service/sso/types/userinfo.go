package types

// UserInfo represents user information retrieved from an SSO provider
type UserInfo struct {
	Subject   string   `json:"sub"`
	Email     string   `json:"email"`
	Name      string   `json:"name"`
	FirstName string   `json:"given_name"`
	LastName  string   `json:"family_name"`
	Groups    []string `json:"groups"`
	// RawGroups holds the raw IdP claim-group identifiers (e.g. "groups:ccf-admins",
	// "hd:example.com", "github-organization:acme") BEFORE translation through group_mapping.
	// Groups (above) is the config-mapped native names used for required-login enforcement and
	// link display; RawGroups is what the login sync translates through the DB SSOGroupMapping
	// rows to materialize native memberships (BCH-1331).
	RawGroups    []string               `json:"-"`
	HostedDomain string                 `json:"hd"`
	Claims       map[string]interface{} `json:"-"`
}
