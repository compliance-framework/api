package assessment

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

type Activity struct {
	Uuid  oscal.Uuid `json:"uuid"`
	Title string     `json:"title"`
	oscal.ComprehensiveDetails
	ResponsibleRoles []oscal.Uuid `json:"responsibleRoles"`
	Steps            []Step       `json:"steps"`
}

type Step struct {
	Uuid  oscal.Uuid `json:"uuid"`
	Title string     `json:"title"`
	oscal.ComprehensiveDetails
	ResponsibleRoles []oscal.Uuid `json:"responsibleRoles"`
	Objectives       []Objective  `json:"objectives"`
}
