package domain

type ActorType string

const (
	ActorTypeTool               ActorType = "tool"
	ActorTypeAssessmentPlatform ActorType = "assessment-platform"
	ActorTypeParty              ActorType = "party"
)

type Actor struct {
	Uuid        Uuid       `json:"uuid"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`

	Links   []Link `json:"links,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	RoleId Uuid      `json:"roleId"`
	Type   ActorType `json:"type"`
}
