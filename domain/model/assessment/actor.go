package assessment

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type ActorType string

const (
	ActorTypeTool               ActorType = "tool"
	ActorTypeAssessmentPlatform ActorType = "assessment-platform"
	ActorTypeParty              ActorType = "party"
)

type Actor struct {
	Uuid model.Uuid `json:"uuid"`
	model.ComprehensiveDetails

	RoleId model.Uuid `json:"roleId"`
	Type   ActorType  `json:"type"`
}
