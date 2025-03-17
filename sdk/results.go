package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
)

type resultClient struct {
	httpClient *http.Client
	config     *Config
}

type Observation struct {
	Collected        time.Time                         `json:"collected" yaml:"collected"`
	Description      string                            `json:"description" yaml:"description"`
	Expires          *time.Time                        `json:"expires,omitempty" yaml:"expires,omitempty"`
	Links            *[]oscaltypes113.Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Methods          []string                          `json:"methods" yaml:"methods"`
	Origins          *[]oscaltypes113.Origin           `json:"origins,omitempty" yaml:"origins,omitempty"`
	Props            *[]oscaltypes113.Property         `json:"props,omitempty" yaml:"props,omitempty"`
	RelevantEvidence *[]oscaltypes113.RelevantEvidence `json:"relevant-evidence,omitempty" yaml:"relevant-evidence,omitempty"`
	Remarks          string                            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Subjects         *[]oscaltypes113.SubjectReference `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	Title            string                            `json:"title,omitempty" yaml:"title,omitempty"`
	Types            *[]string                         `json:"types,omitempty" yaml:"types,omitempty"`
	UUID             string                            `json:"uuid" yaml:"uuid"`
	Labels           map[string]string                 `json:"labels" yaml:"labels"`
}

type Finding struct {
	Description                 string                              `json:"description" yaml:"description"`
	ImplementationStatementUuid string                              `json:"implementation-statement-uuid,omitempty" yaml:"implementation-statement-uuid,omitempty"`
	Links                       *[]oscaltypes113.Link               `json:"links,omitempty" yaml:"links,omitempty"`
	Origins                     *[]oscaltypes113.Origin             `json:"origins,omitempty" yaml:"origins,omitempty"`
	Props                       *[]oscaltypes113.Property           `json:"props,omitempty" yaml:"props,omitempty"`
	RelatedObservations         *[]oscaltypes113.RelatedObservation `json:"related-observations,omitempty" yaml:"related-observations,omitempty"`
	RelatedRisks                *[]oscaltypes113.AssociatedRisk     `json:"related-risks,omitempty" yaml:"related-risks,omitempty"`
	Remarks                     string                              `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Target                      oscaltypes113.FindingTarget         `json:"target" yaml:"target"`
	Title                       string                              `json:"title" yaml:"title"`
	UUID                        string                              `json:"uuid" yaml:"uuid"`
	Labels                      map[string]string                   `json:"labels" yaml:"labels"`
}

type Result struct {
	// Here we override the ID field to be of UUID for compatibility in our SDK.
	// Our clients don't care about Mongo ObjectIDs, and it won't map well for their use.
	UUID     *uuid.UUID        `json:"uuid" yaml:"uuid" bson:"_id"`
	StreamID uuid.UUID         `json:"streamId" yaml:"streamId" bson:"streamId"`
	Labels   map[string]string `json:"labels" yaml:"labels" bson:"labels"`

	AssessmentLog    *oscaltypes113.AssessmentLog           `json:"assessment-log,omitempty" yaml:"assessment-log,omitempty"`
	Attestations     *[]oscaltypes113.AttestationStatements `json:"attestations,omitempty" yaml:"attestations,omitempty"`
	Description      string                                 `json:"description" yaml:"description"`
	End              *time.Time                             `json:"end,omitempty" yaml:"end,omitempty"`
	Findings         *[]Finding                             `json:"findings,omitempty" yaml:"findings,omitempty"`
	Links            *[]oscaltypes113.Link                  `json:"links,omitempty" yaml:"links,omitempty"`
	LocalDefinitions *oscaltypes113.LocalDefinitions        `json:"local-definitions,omitempty" yaml:"local-definitions,omitempty"`
	Observations     *[]Observation                         `json:"observations,omitempty" yaml:"observations,omitempty"`
	Props            *[]oscaltypes113.Property              `json:"props,omitempty" yaml:"props,omitempty"`
	Remarks          string                                 `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	ReviewedControls oscaltypes113.ReviewedControls         `json:"reviewed-controls" yaml:"reviewed-controls"`
	Risks            *[]oscaltypes113.Risk                  `json:"risks,omitempty" yaml:"risks,omitempty"`
	Start            time.Time                              `json:"start" yaml:"start"`
	Title            string                                 `json:"title" yaml:"title"`
}

func (r *resultClient) Create(result *Result) (*Result, error) {
	reqBody, _ := json.Marshal(result)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/assessment-results", r.config.BaseURL), bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(bodyBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
