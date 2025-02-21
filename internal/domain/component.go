package domain

type ComponentType int

const (
	InterconnectionComponentType ComponentType = iota
	SoftwareComponentType
	HardwareComponentType
	ServiceComponentType
	PolicyComponentType
	PhysicalComponentType
	ProcessProcedureComponentType
	PlanComponentType
	GuidanceComponentType
	StandardComponentType
	ValidationComponentType
)
