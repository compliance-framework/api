package types

// UserInfo represents user information retrieved from an SSO provider
type UserInfo struct {
	Subject      string                 `json:"sub"`
	Email        string                 `json:"email"`
	Name         string                 `json:"name"`
	FirstName    string                 `json:"given_name"`
	LastName     string                 `json:"family_name"`
	Groups       []string               `json:"groups"`
	HostedDomain string                 `json:"hd"`
	Claims       map[string]interface{} `json:"-"`
}
