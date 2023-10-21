package identity

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type Role struct {
	Uuid string `json:"uuid"`

	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Props       []model.Property `json:"props,omitempty"`
	Links       []model.Link     `json:"links,omitempty"`
	Remarks     string           `json:"remarks,omitempty"`

	// PartyUuids holds the UUIDs of the `Party` data. Supports many-to-many relationship.
	PartyUuids []string `json:"partyUuids"`
}
