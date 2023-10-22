package domain

type Activity struct {
	Uuid             Uuid       `json:"uuid"`
	Title            string     `json:"title,omitempty"`
	Description      string     `json:"description,omitempty"`
	Props            []Property `json:"props,omitempty"`
	Links            []Link     `json:"links,omitempty"`
	Remarks          string     `json:"remarks,omitempty"`
	ResponsibleRoles []Uuid     `json:"responsibleRoles"`
	Steps            []Step     `json:"steps"`
}

type Step struct {
	Uuid             Uuid        `json:"uuid"`
	Title            string      `json:"title,omitempty"`
	Description      string      `json:"description,omitempty"`
	Props            []Property  `json:"props,omitempty"`
	Links            []Link      `json:"links,omitempty"`
	Remarks          string      `json:"remarks,omitempty"`
	ResponsibleRoles []Uuid      `json:"responsibleRoles"`
	Objectives       []Objective `json:"objectives"`
}
