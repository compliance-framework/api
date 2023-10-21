package identity

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type PartyType int

const (
	Person PartyType = iota
	Group
	Organization
)

type Party struct {
	Uuid string `json:"uuid"`

	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Props       []model.Property `json:"props,omitempty"`
	Links       []model.Link     `json:"links,omitempty"`
	Remarks     string           `json:"remarks,omitempty"`

	// Parties represents the UUIDs of the child `Party` data
	Parties []model.Uuid `json:"parties"`

	// Roles represents the UUIDs of the `Role` responsible for the action.
	Roles []model.Uuid `json:"roles"`
	Type  PartyType    `json:"type"`
}
