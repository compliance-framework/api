package domain

type ActorType string

const (
	ActorTypeTool               ActorType = "tool"
	ActorTypeAssessmentPlatform ActorType = "assessment-platform"
	ActorTypeParty              ActorType = "party"
)
