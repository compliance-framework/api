package domain

// Part An annotated, markup-based textual element of a catalog's or catalog group's definition, or a child of another part.
type Part struct {
	// An optional textual providing a sub-type or characterization of the part's name, or a category to which the part belongs.
	Class string `json:"class,omitempty" yaml:"class,omitempty"`

	// A unique identifier for the part.
	Id    string `json:"id,omitempty" yaml:"id,omitempty"`
	Links []Link `json:"links,omitempty" yaml:"links,omitempty"`

	// A textual label that uniquely identifies the part's semantic type, which exists in a value space qualified by the ns.
	Name string `json:"name" yaml:"name"`

	// An optional namespace qualifying the part's name. This allows different organizations to associate distinct semantics with the same name.
	Ns    string     `json:"ns,omitempty" yaml:"ns,omitempty"`
	Props []Property `json:"props,omitempty" yaml:"props,omitempty"`

	// Permits multiple paragraphs, lists, tables etc.
	Prose string `json:"prose,omitempty" yaml:"prose,omitempty"`

	// An optional name given to the part, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty" yaml:"title,omitempty"`
}
