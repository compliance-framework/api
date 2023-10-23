package domain

type Parameter struct {
	Uuid        Uuid               `json:"uuid"`
	Class       string             `json:"class"`
	Props       []Property         `json:"props"`
	Links       []Link             `json:"links"`
	Label       string             `json:"label"`
	Usage       string             `json:"usage"`
	Constraints []Constraint       `json:"constraints"`
	Guidelines  []Guideline        `json:"guidelines"`
	Values      []string           `json:"values"`
	Select      ParameterSelection `json:"select"`
	Remarks     string             `json:"remarks"`
}

type Constraint struct {
	Description string `json:"description"`
	Tests       []ConstraintTest
}

type ConstraintTest struct {
	Expression string `json:"expression"`
	Remarks    string `json:"remarks"`
}

type Guideline struct {
	Prose string `json:"prose"`
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
