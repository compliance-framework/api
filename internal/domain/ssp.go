package domain

type OperationalStatus int

const (
	Disposition OperationalStatus = iota
	Operational
	Other
	UnderDevelopment
	UnderMajorModification
)
