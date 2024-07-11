package domain

type ActorType string

const (
	ActorTypeTool               ActorType = "tool"
	ActorTypeAssessmentPlatform ActorType = "assessment-platform"
	ActorTypeParty              ActorType = "party"
)

type Actor struct {
	Uuid        Uuid       `json:"uuid" yaml:"uuid"`
	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`

	Links   []Link `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks string `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	RoleId Uuid      `json:"roleId" yaml:"roleId"`
	Type   ActorType `json:"type" yaml:"type"`
}
