package domain

type Control struct {
	Uuid Uuid `json:"uuid" yaml:"uuid"`

	Props []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Parts []Part     `json:"parts,omitempty" yaml:"parts,omitempty"`

	Class    string      `json:"class" yaml:"class"`
	Title    string      `json:"title" yaml:"title"`
	Params   []Parameter `json:"params" yaml:"params"`
	Controls []Uuid      `json:"controlUuids" yaml:"controlUuids"` // Reference to controls
}
