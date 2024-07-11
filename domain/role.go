package domain

type Role struct {
	Uuid string `json:"uuid" yaml:"uuid"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// PartyUuids holds the UUIDs of the `Party` data. Supports many-to-many relationship.
	PartyUuids []string `json:"partyUuids" yaml:"partyUuids"`
}
