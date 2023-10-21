package identity

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type Role struct {
	Uuid string `json:"uuid"`

	model.ComprehensiveDetails

	// PartyUuids holds the UUIDs of the `Party` data. Supports many-to-many relationship.
	PartyUuids []string `json:"partyUuids"`
}
