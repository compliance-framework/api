package assessment

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

type ActorType string

const (
	ActorTypeTool               ActorType = "tool"
	ActorTypeAssessmentPlatform ActorType = "assessment-platform"
	ActorTypeParty              ActorType = "party"
)

type Actor struct {
	Uuid oscal.Uuid `json:"uuid"`
	oscal.ComprehensiveDetails

	RoleId oscal.Uuid `json:"roleId"`
	Type   ActorType  `json:"type"`
}
