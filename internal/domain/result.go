package domain

type ObservationMethod string

const (
	ObservationMethodExamine   ObservationMethod = "examine"
	ObservationMethodInterview ObservationMethod = "interview"
	ObservationMethodTest      ObservationMethod = "test"
	ObservationMethodUnknown   ObservationMethod = "unknown"
)

type ObservationType string

const (
	ObservationTypeSSPStatementIssue ObservationType = "ssp-statement-issue"
	ObservationTypeControlObjective  ObservationType = "control-objective"
	ObservationTypeMitigation        ObservationType = "mitigation"
	ObservationTypeFinding           ObservationType = "finding"
	ObservationTypeHistoric          ObservationType = "historic"
)

type RiskStatus string

const (
	RiskStatusOpen               RiskStatus = "open"
	RiskStatusInvestigating      RiskStatus = "investigating"
	RiskStatusRemediating        RiskStatus = "remediating"
	RiskStatusDeviationRequested RiskStatus = "deviation-requested"
	RiskStatusDeviationApproved  RiskStatus = "deviation-approved"
	RiskStatusClosed             RiskStatus = "closed"
)
