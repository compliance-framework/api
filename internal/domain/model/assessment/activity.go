package assessment

import (
	"github.com/compliance-framework/configuration-service/internal/domain/model"
)

type Activity struct {
	Uuid  model.Uuid `json:"uuid"`
	Title string     `json:"title"`
	model.ComprehensiveDetails
	ResponsibleRoles []model.Uuid `json:"responsibleRoles"`
	Steps            []Step       `json:"steps"`
}

type Step struct {
	Uuid  model.Uuid `json:"uuid"`
	Title string     `json:"title"`
	model.ComprehensiveDetails
	ResponsibleRoles []model.Uuid `json:"responsibleRoles"`
	Objectives       []Objective  `json:"objectives"`
}
