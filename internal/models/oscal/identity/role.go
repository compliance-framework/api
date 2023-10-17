package identity

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Role struct {
	Uuid    string           `json:"uuid"`
	Props   []oscal.Property `json:"props"`
	Links   []metadata.Link  `json:"links"`
	Remarks string           `json:"remarks"`
	// PartyUuids holds the UUIDs of the `Party` data. Supports many-to-many relationship.
	PartyUuids []string `json:"partyUuids"`
}
