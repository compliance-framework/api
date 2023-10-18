package identity

import "github.com/compliance-framework/configuration-service/internal/models/oscal"

type Role struct {
	Uuid string `json:"uuid"`

	oscal.ComprehensiveDetails

	// PartyUuids holds the UUIDs of the `Party` data. Supports many-to-many relationship.
	PartyUuids []string `json:"partyUuids"`
}
