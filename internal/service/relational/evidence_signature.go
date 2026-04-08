package relational

import "time"

type EvidenceSignature struct {
	Version            string                  `json:"version"`
	SignatureAlgorithm string                  `json:"signature_algorithm"`
	SignedAt           time.Time               `json:"signed_at"`
	ContentHash        Hash                    `json:"content_hash"`
	Signer             EvidenceSignatureSigner `json:"signer"`
	Claims             EvidenceSignatureClaims `json:"claims"`
	JWS                string                  `json:"jws"`
}

type EvidenceSignatureSigner struct {
	Type         string `json:"type"`
	ID           string `json:"id,omitempty"`
	Email        string `json:"email,omitempty"`
	Name         string `json:"name,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
}

type EvidenceSignatureClaims struct {
	TokenKind    string     `json:"token_kind,omitempty"`
	Subject      string     `json:"subject,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	IssuedAt     *time.Time `json:"issued_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	GivenName    string     `json:"given_name,omitempty"`
	FamilyName   string     `json:"family_name,omitempty"`
	AgentID      string     `json:"agent_id,omitempty"`
	CredentialID string     `json:"credential_id,omitempty"`
	AuthMethod   string     `json:"auth_method,omitempty"`
}
