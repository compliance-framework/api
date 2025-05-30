package relational

import (
	"encoding/json"
	"testing"
	"time"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestPlanOfActionAndMilestones_MarshalUnmarshalOscal tests the marshaling and unmarshaling of PlanOfActionAndMilestones
// to and from OSCAL format. It ensures that the conversion process preserves all fields and structure.
func TestPlanOfActionAndMilestones_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.PlanOfActionAndMilestones
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.PlanOfActionAndMilestones{
				UUID: uuid.New().String(),
				Metadata: oscalTypes_1_1_3.Metadata{
					Title:        "Minimal POAM",
					LastModified: time.Now(),
					Version:      "1.0.0",
					OscalVersion: "1.1.3",
				},
				PoamItems: []oscalTypes_1_1_3.PoamItem{
					{
						UUID:        uuid.New().String(),
						Title:       "Test POAM Item",
						Description: "A test POAM item",
					},
				},
			},
		},
		{
			name: "with risks",
			data: oscalTypes_1_1_3.PlanOfActionAndMilestones{
				UUID: uuid.New().String(),
				Metadata: oscalTypes_1_1_3.Metadata{
					Title:        "POAM with Risks",
					LastModified: time.Now(),
					Version:      "1.0.0",
					OscalVersion: "1.1.3",
				},
				PoamItems: []oscalTypes_1_1_3.PoamItem{
					{
						UUID:        uuid.New().String(),
						Title:       "Test POAM Item with Risks",
						Description: "A test POAM item with associated risks",
					},
				},
				Risks: &[]oscalTypes_1_1_3.Risk{
					{
						UUID:        uuid.New().String(),
						Title:       "Test Risk",
						Description: "A test security risk",
						Statement:   "This is a risk statement",
						Status:      "open",
					},
				},
			},
		},
		{
			name: "with back matter",
			data: oscalTypes_1_1_3.PlanOfActionAndMilestones{
				UUID: uuid.New().String(),
				Metadata: oscalTypes_1_1_3.Metadata{
					Title:        "POAM with BackMatter",
					LastModified: time.Now(),
					Version:      "1.0.0",
					OscalVersion: "1.1.3",
				},
				PoamItems: []oscalTypes_1_1_3.PoamItem{
					{
						UUID:        uuid.New().String(),
						Title:       "Test POAM Item",
						Description: "A test POAM item",
					},
				},
				BackMatter: &oscalTypes_1_1_3.BackMatter{
					Resources: &[]oscalTypes_1_1_3.Resource{
						{
							UUID:        uuid.New().String(),
							Title:       "Resource 1",
							Description: "A test resource",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			poam := &PlanOfActionAndMilestones{}
			assert.NotPanics(t, func() {
				poam.UnmarshalOscal(tt.data)
			})
			output := poam.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestRisk_MarshalUnmarshalOscal tests the marshaling and unmarshaling of Risk
// to and from OSCAL format. It ensures that the conversion process preserves all fields and structure.
func TestRisk_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Risk
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.Risk{
				UUID:        uuid.New().String(),
				Title:       "Minimal Risk",
				Description: "A minimal risk description",
				Statement:   "This is a risk statement",
				Status:      "open",
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.Risk{
				UUID:        uuid.New().String(),
				Title:       "Full Risk",
				Description: "A comprehensive risk description",
				Statement:   "This is a detailed risk statement",
				Status:      "investigating",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "risk-level", Value: "high"},
					{Name: "category", Value: "security"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com/risk", Text: "Risk Documentation"},
				},
				Origins: &[]oscalTypes_1_1_3.Origin{
					{
						Actors: []oscalTypes_1_1_3.OriginActor{
							{
								ActorUuid: uuid.New().String(),
								Type:      "tool",
							},
						},
					},
				},
				ThreatIds: &[]oscalTypes_1_1_3.ThreatId{
					{
						System: "https://cve.mitre.org",
						ID:     "CVE-2023-1234",
					},
				},
				Characterizations: &[]oscalTypes_1_1_3.Characterization{
					{
						Origin: oscalTypes_1_1_3.Origin{
							Actors: []oscalTypes_1_1_3.OriginActor{
								{
									ActorUuid: uuid.New().String(),
									Type:      "assessment-platform",
								},
							},
						},
						Facets: []oscalTypes_1_1_3.Facet{
							{
								Name:   "likelihood",
								System: "https://doi.org/10.6028/NIST.SP.800-30r1",
								Value:  "high",
							},
						},
					},
				},
				MitigatingFactors: &[]oscalTypes_1_1_3.MitigatingFactor{
					{
						UUID:        uuid.New().String(),
						Description: "Network segmentation in place",
					},
				},
				Deadline: &time.Time{},
				Remediations: &[]oscalTypes_1_1_3.Response{
					{
						UUID:        uuid.New().String(),
						Title:       "Patch System",
						Description: "Apply security patches",
						Lifecycle:   "planned",
					},
				},
				RiskLog: &oscalTypes_1_1_3.RiskLog{
					Entries: []oscalTypes_1_1_3.RiskLogEntry{
						{
							UUID:  uuid.New().String(),
							Start: time.Now(),
							Title: "Risk Identified",
						},
					},
				},
				RelatedObservations: &[]oscalTypes_1_1_3.RelatedObservation{
					{
						ObservationUuid: uuid.New().String(),
					},
				},
			},
		},
		{
			name: "with deadline only",
			data: oscalTypes_1_1_3.Risk{
				UUID:        uuid.New().String(),
				Title:       "Risk with Deadline",
				Description: "A risk with a specific deadline",
				Statement:   "This risk has a deadline",
				Status:      "deviation-requested",
				Deadline:    &time.Time{},
			},
		},
		{
			name: "with threat ids only",
			data: oscalTypes_1_1_3.Risk{
				UUID:        uuid.New().String(),
				Title:       "Risk with Threat IDs",
				Description: "A risk with associated threat identifiers",
				Statement:   "This risk has threat IDs",
				Status:      "closed",
				ThreatIds: &[]oscalTypes_1_1_3.ThreatId{
					{
						System: "https://capec.mitre.org",
						ID:     "CAPEC-1",
					},
					{
						System: "https://cwe.mitre.org",
						ID:     "CWE-79",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			risk := &Risk{}
			assert.NotPanics(t, func() {
				risk.UnmarshalOscal(tt.data)
			})
			output := risk.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestOrigin_MarshalUnmarshalOscal tests the marshaling and unmarshaling of Origin
// to and from OSCAL format, verifying that all fields are correctly handled.
func TestOrigin_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Origin
	}{
		{
			name: "single actor",
			data: oscalTypes_1_1_3.Origin{
				Actors: []oscalTypes_1_1_3.OriginActor{
					{
						ActorUuid: uuid.New().String(),
						Type:      "tool",
					},
				},
			},
		},
		{
			name: "multiple actors with props",
			data: oscalTypes_1_1_3.Origin{
				Actors: []oscalTypes_1_1_3.OriginActor{
					{
						ActorUuid: uuid.New().String(),
						Type:      "assessment-platform",
						RoleId:    "assessor",
						Props: &[]oscalTypes_1_1_3.Property{
							{Name: "version", Value: "1.0"},
						},
					},
					{
						ActorUuid: uuid.New().String(),
						Type:      "party",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			origin := &Origin{}
			origin.UnmarshalOscal(tt.data)
			output := origin.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestThreatId_MarshalUnmarshalOscal tests the marshaling and unmarshaling of ThreatId
// to and from OSCAL format.
func TestThreatId_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.ThreatId
	}{
		{
			name: "CVE threat id",
			data: oscalTypes_1_1_3.ThreatId{
				System: "https://cve.mitre.org",
				ID:     "CVE-2023-1234",
			},
		},
		{
			name: "CAPEC threat id with href",
			data: oscalTypes_1_1_3.ThreatId{
				System: "https://capec.mitre.org",
				ID:     "CAPEC-63",
				Href:   "https://capec.mitre.org/data/definitions/63.html",
			},
		},
		{
			name: "CWE threat id",
			data: oscalTypes_1_1_3.ThreatId{
				System: "https://cwe.mitre.org",
				ID:     "CWE-79",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			threatId := &ThreatId{}
			threatId.UnmarshalOscal(tt.data)
			output := threatId.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestCharacterization_MarshalUnmarshalOscal tests the marshaling and unmarshaling of Characterization
// to and from OSCAL format.
func TestCharacterization_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Characterization
	}{
		{
			name: "likelihood characterization",
			data: oscalTypes_1_1_3.Characterization{
				Origin: oscalTypes_1_1_3.Origin{
					Actors: []oscalTypes_1_1_3.OriginActor{
						{
							ActorUuid: uuid.New().String(),
							Type:      "assessment-platform",
						},
					},
				},
				Facets: []oscalTypes_1_1_3.Facet{
					{
						Name:   "likelihood",
						System: "https://doi.org/10.6028/NIST.SP.800-30r1",
						Value:  "high",
					},
				},
			},
		},
		{
			name: "impact characterization with multiple facets",
			data: oscalTypes_1_1_3.Characterization{
				Origin: oscalTypes_1_1_3.Origin{
					Actors: []oscalTypes_1_1_3.OriginActor{
						{
							ActorUuid: uuid.New().String(),
							Type:      "tool",
						},
					},
				},
				Facets: []oscalTypes_1_1_3.Facet{
					{
						Name:   "impact",
						System: "https://doi.org/10.6028/NIST.SP.800-30r1",
						Value:  "moderate",
					},
					{
						Name:   "confidentiality",
						System: "https://doi.org/10.6028/NIST.SP.800-60v1r1",
						Value:  "fips-199-moderate",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			char := &Characterization{}
			char.UnmarshalOscal(tt.data)
			output := char.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestMitigatingFactor_MarshalUnmarshalOscal tests the marshaling and unmarshaling of MitigatingFactor
// to and from OSCAL format.
func TestMitigatingFactor_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.MitigatingFactor
	}{
		{
			name: "simple mitigating factor",
			data: oscalTypes_1_1_3.MitigatingFactor{
				UUID:        uuid.New().String(),
				Description: "Network segmentation is in place",
			},
		},
		{
			name: "complex mitigating factor",
			data: oscalTypes_1_1_3.MitigatingFactor{
				UUID:               uuid.New().String(),
				Description:        "Multi-factor authentication implemented",
				ImplementationUuid: uuid.New().String(),
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "effectiveness", Value: "high"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com/mfa", Text: "MFA Documentation"},
				},
				Subjects: &[]oscalTypes_1_1_3.SubjectReference{
					{
						SubjectUuid: uuid.New().String(),
						Type:        "component",
						Title:       "Authentication Service",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			factor := &MitigatingFactor{}
			factor.UnmarshalOscal(tt.data)
			output := factor.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestResponse_MarshalUnmarshalOscal tests the marshaling and unmarshaling of Response
// to and from OSCAL format.
func TestResponse_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Response
	}{
		{
			name: "simple response",
			data: oscalTypes_1_1_3.Response{
				UUID:        uuid.New().String(),
				Title:       "Apply Security Patch",
				Description: "Install the latest security patches",
				Lifecycle:   "planned",
			},
		},
		{
			name: "complex response with tasks",
			data: oscalTypes_1_1_3.Response{
				UUID:        uuid.New().String(),
				Title:       "Comprehensive Security Update",
				Description: "Multi-step security remediation",
				Lifecycle:   "in-progress",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "priority", Value: "high"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com/remediation", Text: "Remediation Guide"},
				},
				Origins: &[]oscalTypes_1_1_3.Origin{
					{
						Actors: []oscalTypes_1_1_3.OriginActor{
							{
								ActorUuid: uuid.New().String(),
								Type:      "party",
							},
						},
					},
				},
				Tasks: &[]oscalTypes_1_1_3.Task{
					{
						UUID:        uuid.New().String(),
						Type:        "milestone",
						Title:       "Patch Testing",
						Description: "Test patches in staging environment",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			response := &Response{}
			response.UnmarshalOscal(tt.data)
			output := response.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestRiskLog_MarshalUnmarshalOscal tests the marshaling and unmarshaling of RiskLog
// to and from OSCAL format.
func TestRiskLog_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.RiskLog
	}{
		{
			name: "simple risk log",
			data: oscalTypes_1_1_3.RiskLog{
				Entries: []oscalTypes_1_1_3.RiskLogEntry{
					{
						UUID:  uuid.New().String(),
						Start: time.Now(),
						Title: "Risk Identified",
					},
				},
			},
		},
		{
			name: "complex risk log with multiple entries",
			data: oscalTypes_1_1_3.RiskLog{
				Entries: []oscalTypes_1_1_3.RiskLogEntry{
					{
						UUID:         uuid.New().String(),
						Start:        time.Now(),
						Title:        "Risk Identified",
						Description:  "Initial risk identification",
						StatusChange: "open",
					},
					{
						UUID:         uuid.New().String(),
						Start:        time.Now().Add(24 * time.Hour),
						Title:        "Risk Investigation Started",
						Description:  "Beginning investigation of the risk",
						StatusChange: "investigating",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			riskLog := &RiskLog{}
			riskLog.UnmarshalOscal(tt.data)
			output := riskLog.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestRelatedObservation_MarshalUnmarshalOscal tests the marshaling and unmarshaling of RelatedObservation
// to and from OSCAL format.
func TestRelatedObservation_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.RelatedObservation
	}{
		{
			name: "simple related observation",
			data: oscalTypes_1_1_3.RelatedObservation{
				ObservationUuid: uuid.New().String(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			relObs := &RelatedObservation{}
			relObs.UnmarshalOscal(tt.data)
			output := relObs.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}