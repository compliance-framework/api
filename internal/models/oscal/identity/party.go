package identity

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

type PartyType int

const (
	Person PartyType = iota
	Group
	Organization
)

type Party struct {
	Uuid string `json:"uuid"`

	oscal.ComprehensiveDetails

	// Parties represents the UUIDs of the child `Party` data
	Parties []oscal.Uuid `json:"parties"`

	// Roles represents the UUIDs of the `Role` responsible for the action.
	Roles []oscal.Uuid `json:"roles"`
	Type  PartyType    `json:"type"`
}
