package domain

import "time"

type Metadata struct {
	Revisions             []Revision `json:"revisions"`
	PartyUuids            []string   `json:"partyUuids"`
	ResponsiblePartyUuids []string   `json:"responsiblePartyUuids"`
	RoleUuids             []string   `json:"roleUuids"`
	Actions               []Action   `json:"actions"`
}

type Revision struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Published    time.Time `json:"published"`
	LastModified time.Time `json:"lastModified"`
	Version      string    `json:"version"`
	OscalVersion string    `json:"oscalVersion"`
}

type ComprehensiveDetails struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`
}
