package model

type Metadata struct {
	Revision              Revision   `json:"revision"`
	Revisions             []Revision `json:"revisions"`
	PartyUuids            []string   `json:"partyUuids"`
	ResponsiblePartyUuids []string   `json:"responsiblePartyUuids"`
	RoleUuids             []string   `json:"roleUuids"`
	Actions               []Action   `json:"actions"`
}
