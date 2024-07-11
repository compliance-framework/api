package domain

type Group struct {
	Uuid Uuid `json:"uuid" yaml:"uuid"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	Class  string      `json:"class" yaml:"class"`
	Params []Parameter `json:"params" yaml:"params"`
	Groups []Uuid      `json:"groups" yaml:"groups"`
}
