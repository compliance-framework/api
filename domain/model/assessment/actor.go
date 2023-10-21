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
	Uuid        model.Uuid       `json:"uuid"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Props       []model.Property `json:"props,omitempty"`

	Links   []model.Link `json:"links,omitempty"`
	Remarks string       `json:"remarks,omitempty"`

	RoleId model.Uuid `json:"roleId"`
	Type   ActorType  `json:"type"`
}
