package catalog

import (
	model2 "github.com/compliance-framework/configuration-service/domain/model"
)

type Parameter struct {
	Uuid        model2.Uuid       `json:"uuid"`
	Class       string            `json:"class"`
	Props       []model2.Property `json:"props"`
	Links       []model2.Link     `json:"links"`
	Label       string            `json:"label"`
	Usage       string            `json:"usage"`
	Constraints []Constraint      `json:"constraints"`
	Guidelines  []Guideline       `json:"guidelines"`
	Values      []string          `json:"values"`
	Select      Selection         `json:"select"`
	Remarks     string            `json:"remarks"`
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
