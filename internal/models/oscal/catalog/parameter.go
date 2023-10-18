package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Parameter struct {
	Uuid        oscal.Uuid       `json:"uuid"`
	Class       string           `json:"class"`
	Props       []oscal.Property `json:"props"`
	Links       []metadata.Link  `json:"links"`
	Label       string           `json:"label"`
	Usage       string           `json:"usage"`
	Constraints []Constraint     `json:"constraints"`
	Guidelines  []Guideline      `json:"guidelines"`
	Values      []string         `json:"values"`
	Select      Selection        `json:"select"`
	Remarks     string           `json:"remarks"`
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

type Selection struct {
	HowMany HowManyType
	Choices []string
}
