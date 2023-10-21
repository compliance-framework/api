package assessment

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type Activity struct {
	Uuid             model.Uuid       `json:"uuid"`
	Title            string           `json:"title,omitempty"`
	Description      string           `json:"description,omitempty"`
	Props            []model.Property `json:"props,omitempty"`
	Links            []model.Link     `json:"links,omitempty"`
	Remarks          string           `json:"remarks,omitempty"`
	ResponsibleRoles []model.Uuid     `json:"responsibleRoles"`
	Steps            []Step           `json:"steps"`
}

type Step struct {
	Uuid             model.Uuid       `json:"uuid"`
	Title            string           `json:"title,omitempty"`
	Description      string           `json:"description,omitempty"`
	Props            []model.Property `json:"props,omitempty"`
	Links            []model.Link     `json:"links,omitempty"`
	Remarks          string           `json:"remarks,omitempty"`
	ResponsibleRoles []model.Uuid     `json:"responsibleRoles"`
	Objectives       []Objective      `json:"objectives"`
}
