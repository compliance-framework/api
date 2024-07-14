package domain

type PartyType int

const (
	PersonPartyType PartyType = iota
	GroupPartyType
	OrganizationPartyType
)

type Party struct {
	Uuid string `json:"uuid" yaml:"uuid"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// Parties represents the UUIDs of the child `Party` data
	Parties []Uuid `json:"parties" yaml:"parties"`

	// Roles represents the UUIDs of the `Role` responsible for the action.
	Roles []Uuid    `json:"roles" yaml:"roles"`
	Type  PartyType `json:"type" yaml:"type"`
}
