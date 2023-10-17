package identity

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type PartyType int

const (
	Person PartyType = iota
	Group
	Organization
)

type Party struct {
	Uuid  string          `json:"uuid"`
	Links []metadata.Link `json:"links"`

	// Parties represents the UUIDs of the child `Party` data
	Parties []oscal.Uuid     `json:"parties"`
	Props   []oscal.Property `json:"props"`
	Remarks string           `json:"remarks"`

	// Roles represents the UUIDs of the `Role` responsible for the action.
	Roles []oscal.Uuid `json:"roles"`
	Type  PartyType    `json:"type"`
}
