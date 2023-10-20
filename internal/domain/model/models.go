package model

type Uuid string

type Links struct {
	Links []Link `json:"links,omitempty"`
}

type Parts struct {
	Parts []Part `json:"parts,omitempty"`
}

type Props struct {
	Props []Property `json:"props,omitempty"`
}

type Remarks struct {
	Remarks string `json:"remarks,omitempty"`
}

type ComprehensiveDetails struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Props
	Links
	Remarks
}

type Selection struct {
	IncludeAll bool   `json:"includeAll"`
	Exclude    []Uuid `json:"exclude"`
	Include    []Uuid `json:"include"`
}
