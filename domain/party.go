package domain

type PartyType int

const (
	PersonPartyType PartyType = iota
	GroupPartyType
	OrganizationPartyType
)

type Party struct {
	Uuid string `json:"uuid"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	// Parties represents the UUIDs of the child `Party` data
	Parties []Uuid `json:"parties"`

	// Roles represents the UUIDs of the `Role` responsible for the action.
	Roles []Uuid    `json:"roles"`
	Type  PartyType `json:"type"`
}
