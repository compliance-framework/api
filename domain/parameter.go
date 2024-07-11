package domain

type Parameter struct {
	Uuid        Uuid               `json:"uuid" yaml:"uuid"`
	Class       string             `json:"class" yaml:"class"`
	Props       []Property         `json:"props" yaml:"props"`
	Links       []Link             `json:"links" yaml:"links"`
	Label       string             `json:"label" yaml:"label"`
	Usage       string             `json:"usage" yaml:"usage"`
	Constraints []Constraint       `json:"constraints" yaml:"constraints"`
	Guidelines  []Guideline        `json:"guidelines" yaml:"guidelines"`
	Values      []string           `json:"values" yaml:"values"`
	Select      ParameterSelection `json:"select" yaml:"select"`
	Remarks     string             `json:"remarks" yaml:"remarks"`
}

type Constraint struct {
	Description string           `json:"description" yaml:"description"`
	Tests       []ConstraintTest `json:"tests" yaml:"tests"`
}

type ConstraintTest struct {
	Expression string `json:"expression" yaml:"expression"`
	Remarks    string `json:"remarks" yaml:"remarks"`
}

type Guideline struct {
	Prose string `json:"prose" yaml:"prose"`
}

type HowManyType int

const (
	AllOf HowManyType = iota
	OneOf
	OneOrMore
)

type ParameterSelection struct {
	HowMany HowManyType
	Choices []string
}
