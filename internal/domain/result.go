package domain

import (
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
)

type Result struct {
	// Here we override the ID field to be of UUID for compatibility in our SDK.
	// Our clients don't care about Mongo ObjectIDs, and it won't map well for their use.
	UUID                 *uuid.UUID        `json:"uuid" yaml:"uuid" bson:"_id"`
	StreamID             uuid.UUID         `json:"streamId" yaml:"streamId" bson:"streamId"`
	Labels               map[string]string `json:"labels" yaml:"labels" bson:"labels"`
	oscaltypes113.Result `bson:",inline"`
}

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
