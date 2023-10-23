package domain

type Group struct {
	Uuid Uuid `json:"uuid"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Class  string      `json:"class"`
	Params []Parameter `json:"params"`
	Groups []Uuid      `json:"groups"`
}
