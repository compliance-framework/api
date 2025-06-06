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
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.PlanOfActionAndMilestones{
				UUID: uuid.New().String(),
				Metadata: oscalTypes_1_1_3.Metadata{
					Title:        "Full POAM",
					LastModified: time.Now(),
					Version:      "2.0.0",
					OscalVersion: "1.1.3",
				},
				ImportSsp: &oscalTypes_1_1_3.ImportSsp{
					Href:    "#import-ssp-1",
					Remarks: "Import SSP remarks",
				},
				SystemId: &oscalTypes_1_1_3.SystemId{
					ID:             "system-1",
					IdentifierType: "https://ietf.org/rfc/rfc4122",
				},
				LocalDefinitions: &oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions{
					Remarks: "Local definitions remarks",
				},
				Observations: &[]oscalTypes_1_1_3.Observation{
					{
						UUID:        uuid.New().String(),
						Title:       "Observation 1",
						Description: "An observation",
						Collected:   time.Now(),
						Methods:     []string{"EXAMINE", "INTERVIEW"},
					},
				},
				Risks: &[]oscalTypes_1_1_3.Risk{
					{
						UUID:        uuid.New().String(),
						Title:       "Risk 1",
						Description: "A risk",
						Statement:   "Risk statement",
						Status:      "open",
					},
				},
				PoamItems: []oscalTypes_1_1_3.PoamItem{
					{
						UUID:        uuid.New().String(),
						Title:       "POAM Item 1",
						Description: "A POAM item",
					},
				},
				Findings: &[]oscalTypes_1_1_3.Finding{
					{
						UUID:        uuid.New().String(),
						Title:       "Finding 1",
						Description: "A finding",
						Target: oscalTypes_1_1_3.FindingTarget{
							Type:     "objective-id",
							TargetId: "objective-1",
							Status: oscalTypes_1_1_3.ObjectiveStatus{
								State: "satisfied",
							},
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
			testParentID := uuid.New()
			assert.NotPanics(t, func() {
				risk.UnmarshalOscal(tt.data, testParentID, "TestParent")
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

// TestObservation_MarshalUnmarshalOscal tests the marshaling and unmarshaling of Observation
// to and from OSCAL format. It ensures that the conversion process preserves all fields and structure.
func TestObservation_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Observation
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.Observation{
				UUID:        uuid.New().String(),
				Title:       "Minimal Observation",
				Description: "A minimal observation",
				Collected:   time.Now(),
				Methods:     []string{"EXAMINE"},
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.Observation{
				UUID:        uuid.New().String(),
				Title:       "Full Observation",
				Description: "A full observation",
				Collected:   time.Now(),
				Methods:     []string{"EXAMINE", "INTERVIEW", "TEST"},
				Expires:     &time.Time{},
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "type", Value: "security"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com", Text: "Example"},
				},
				Origins: &[]oscalTypes_1_1_3.Origin{
					{
						Actors: []oscalTypes_1_1_3.OriginActor{
							{
								Type:      "party",
								ActorUuid: uuid.New().String(),
							},
						},
					},
				},
				RelevantEvidence: &[]oscalTypes_1_1_3.RelevantEvidence{
					{
						Description: "Evidence description",
						Href:        "http://evidence.com",
					},
				},
				Subjects: &[]oscalTypes_1_1_3.SubjectReference{
					{
						Type:        "component",
						SubjectUuid: uuid.New().String(),
					},
				},
				Types:   &[]string{"security", "compliance"},
				Remarks: "Observation remarks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			obs := &Observation{}
			testParentID := uuid.New()
			obs.UnmarshalOscal(tt.data, &testParentID, "TestParent")
			output := obs.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestFinding_MarshalUnmarshalOscal tests the marshaling and unmarshaling of Finding
// to and from OSCAL format. It ensures that the conversion process preserves all fields and structure.
func TestFinding_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.Finding
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.Finding{
				UUID:        uuid.New().String(),
				Title:       "Minimal Finding",
				Description: "A minimal finding",
				Target: oscalTypes_1_1_3.FindingTarget{
					Type:     "objective-id",
					TargetId: "objective-1",
					Status: oscalTypes_1_1_3.ObjectiveStatus{
						State: "satisfied",
					},
				},
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.Finding{
				UUID:                        uuid.New().String(),
				Title:                       "Full Finding",
				Description:                 "A full finding",
				ImplementationStatementUuid: uuid.New().String(),
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "severity", Value: "medium"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com", Text: "Example"},
				},
				Origins: &[]oscalTypes_1_1_3.Origin{
					{
						Actors: []oscalTypes_1_1_3.OriginActor{
							{
								Type:      "party",
								ActorUuid: uuid.New().String(),
							},
						},
					},
				},
				RelatedObservations: &[]oscalTypes_1_1_3.RelatedObservation{
					{
						ObservationUuid: uuid.New().String(),
					},
				},
				RelatedRisks: &[]oscalTypes_1_1_3.AssociatedRisk{
					{
						RiskUuid: uuid.New().String(),
					},
				},
				Target: oscalTypes_1_1_3.FindingTarget{
					Type:     "objective-id",
					TargetId: "objective-1",
					Title:    "Target title",
					Status: oscalTypes_1_1_3.ObjectiveStatus{
						State:  "not-satisfied",
						Reason: "Missing implementation",
					},
					ImplementationStatus: &oscalTypes_1_1_3.ImplementationStatus{
						State: "partial",
					},
				},
				Remarks: "Finding remarks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			finding := &Finding{}
			testParentID := uuid.New()
			finding.UnmarshalOscal(tt.data, &testParentID, "TestParent")
			output := finding.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestPlanOfActionAndMilestonesLocalDefinitions_MarshalUnmarshalOscal tests the marshaling and unmarshaling of PlanOfActionAndMilestonesLocalDefinitions
// to and from OSCAL format, verifying correct handling of all nested components.
func TestPlanOfActionAndMilestonesLocalDefinitions_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions{
				Remarks: "Minimal local definitions",
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions{
				AssessmentAssets: &oscalTypes_1_1_3.AssessmentAssets{
					AssessmentPlatforms: []oscalTypes_1_1_3.AssessmentPlatform{
						{
							UUID:  uuid.New().String(),
							Title: "Assessment Platform 1",
						},
					},
				},
				Components: &[]oscalTypes_1_1_3.SystemComponent{
					{
						UUID:        uuid.New().String(),
						Type:        "software",
						Title:       "Component 1",
						Description: "System component",
						Status: oscalTypes_1_1_3.SystemComponentStatus{
							State: "operational",
						},
					},
				},
				InventoryItems: &[]oscalTypes_1_1_3.InventoryItem{
					{
						UUID:        uuid.New().String(),
						Description: "Inventory item",
					},
				},
				Remarks: "Full local definitions",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			ld := &PlanOfActionAndMilestonesLocalDefinitions{}
			ld.UnmarshalOscal(tt.data)
			output := ld.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}
// TestPoamItem_MarshalUnmarshalOscal tests the marshaling and unmarshaling of PoamItem
// to and from OSCAL format, ensuring all fields are correctly handled.
func TestPoamItem_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.PoamItem
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.PoamItem{
				UUID:        uuid.New().String(),
				Title:       "Minimal POAM Item",
				Description: "A minimal POAM item",
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.PoamItem{
				UUID:        uuid.New().String(),
				Title:       "Full POAM Item",
				Description: "A comprehensive POAM item",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "priority", Value: "high"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com/poam", Text: "POAM Documentation"},
				},
				Origins: &[]oscalTypes_1_1_3.PoamItemOrigin{
					{
						Actors: []oscalTypes_1_1_3.OriginActor{
							{
								Type:      "party",
								ActorUuid: uuid.New().String(),
							},
						},
					},
				},
				RelatedFindings: &[]oscalTypes_1_1_3.RelatedFinding{
					{
						FindingUuid: uuid.New().String(),
					},
				},
				RelatedObservations: &[]oscalTypes_1_1_3.RelatedObservation{
					{
						ObservationUuid: uuid.New().String(),
					},
				},
				RelatedRisks: &[]oscalTypes_1_1_3.AssociatedRisk{
					{
						RiskUuid: uuid.New().String(),
					},
				},
				Remarks: "POAM item remarks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			poamItem := &PoamItem{}
			testParentID := uuid.New()
			poamItem.UnmarshalOscal(tt.data, testParentID)
			output := poamItem.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestAssessmentAssets_MarshalUnmarshalOscal tests the marshaling and unmarshaling of AssessmentAssets
// to and from OSCAL format, verifying correct conversion of assessment platforms and components.
func TestAssessmentAssets_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.AssessmentAssets
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.AssessmentAssets{
				AssessmentPlatforms: []oscalTypes_1_1_3.AssessmentPlatform{
					{
						UUID:  uuid.New().String(),
						Title: "Minimal Assessment Platform",
					},
				},
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.AssessmentAssets{
				AssessmentPlatforms: []oscalTypes_1_1_3.AssessmentPlatform{
					{
						UUID:  uuid.New().String(),
						Title: "Full Assessment Platform",
						Props: &[]oscalTypes_1_1_3.Property{
							{Name: "type", Value: "automated"},
						},
					},
				},
				Components: &[]oscalTypes_1_1_3.SystemComponent{
					{
						UUID:        uuid.New().String(),
						Type:        "software",
						Title:       "Assessment Component",
						Description: "Component used for assessment",
						Status: oscalTypes_1_1_3.SystemComponentStatus{
							State: "operational",
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

			assets := &AssessmentAssets{}
			assets.UnmarshalOscal(tt.data)
			output := assets.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestRelevantEvidence_MarshalUnmarshalOscal tests the marshaling and unmarshaling of RelevantEvidence
// to and from OSCAL format, ensuring all fields are correctly handled.
func TestRelevantEvidence_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.RelevantEvidence
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.RelevantEvidence{
				Description: "Minimal evidence description",
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.RelevantEvidence{
				Description: "Comprehensive evidence description",
				Href:        "http://example.com/evidence",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "type", Value: "screenshot"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com/related", Text: "Related Evidence"},
				},
				Remarks: "Evidence remarks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			evidence := &RelevantEvidence{}
			evidence.UnmarshalOscal(tt.data)
			output := evidence.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestSubjectReference_MarshalUnmarshalOscal tests the marshaling and unmarshaling of SubjectReference
// to and from OSCAL format, verifying correct handling of subject references.
func TestSubjectReference_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.SubjectReference
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.SubjectReference{
				Type:        "component",
				SubjectUuid: uuid.New().String(),
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.SubjectReference{
				Type:        "inventory-item",
				SubjectUuid: uuid.New().String(),
				Title:       "Subject Reference Title",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "category", Value: "hardware"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com/subject", Text: "Subject Info"},
				},
				Remarks: "Subject reference remarks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			subjectRef := &SubjectReference{}
			subjectRef.UnmarshalOscal(tt.data)
			output := subjectRef.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestFindingTarget_MarshalUnmarshalOscal tests the marshaling and unmarshaling of FindingTarget
// to and from OSCAL format, ensuring all fields are correctly handled.
func TestFindingTarget_MarshalUnmarshalOscal(t *testing.T) {
	tests := []struct {
		name string
		data oscalTypes_1_1_3.FindingTarget
	}{
		{
			name: "minimal fields",
			data: oscalTypes_1_1_3.FindingTarget{
				Type:     "statement-id",
				TargetId: "statement-1",
				Status: oscalTypes_1_1_3.ObjectiveStatus{
					State: "satisfied",
				},
			},
		},
		{
			name: "all fields set",
			data: oscalTypes_1_1_3.FindingTarget{
				Type:        "objective-id",
				TargetId:    "objective-1",
				Title:       "Finding Target Title",
				Description: "Finding target description",
				Status: oscalTypes_1_1_3.ObjectiveStatus{
					State:   "not-satisfied",
					Reason:  "Implementation incomplete",
					Remarks: "Additional work needed",
				},
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "severity", Value: "medium"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "http://example.com/target", Text: "Target Documentation"},
				},
				ImplementationStatus: &oscalTypes_1_1_3.ImplementationStatus{
					State:   "partial",
					Remarks: "Implementation in progress",
				},
				Remarks: "Target remarks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJson, err := json.Marshal(tt.data)
			assert.NoError(t, err)

			target := &FindingTarget{}
			target.UnmarshalOscal(tt.data)
			output := target.MarshalOscal()
			outputJson, err := json.Marshal(output)
			assert.NoError(t, err)

			assert.JSONEq(t, string(inputJson), string(outputJson))
		})
	}
}

// TestAssociatedRisk_MarshalUnmarshalOscal tests the marshaling and unmarshaling of AssociatedRisk
// to and from OSCAL format, verifying correct conversion of risk references.
func TestAssociatedRisk_MarshalUnmarshalOscal(t *testing.T) {
	osc := oscalTypes_1_1_3.AssociatedRisk{
		RiskUuid: uuid.New().String(),
	}
	inputJson, err := json.Marshal(osc)
	assert.NoError(t, err)

	assocRisk := &AssociatedRisk{}
	assocRisk.UnmarshalOscal(osc)
	output := assocRisk.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)

	assert.JSONEq(t, string(inputJson), string(outputJson))
}

// TestRelatedFinding_MarshalUnmarshalOscal tests the marshaling and unmarshaling of RelatedFinding
// to and from OSCAL format, ensuring correct conversion of finding references.
func TestRelatedFinding_MarshalUnmarshalOscal(t *testing.T) {
	osc := oscalTypes_1_1_3.RelatedFinding{
		FindingUuid: uuid.New().String(),
	}
	inputJson, err := json.Marshal(osc)
	assert.NoError(t, err)

	relatedFinding := &RelatedFinding{}
	relatedFinding.UnmarshalOscal(osc)
	output := relatedFinding.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)

	assert.JSONEq(t, string(inputJson), string(outputJson))
}

// TestPoamItemOrigin_MarshalUnmarshalOscal tests the marshaling and unmarshaling of PoamItemOrigin
// to and from OSCAL format, verifying correct handling of POAM item origins.
func TestPoamItemOrigin_MarshalUnmarshalOscal(t *testing.T) {
	osc := oscalTypes_1_1_3.PoamItemOrigin{
		Actors: []oscalTypes_1_1_3.OriginActor{
			{
				Type:      "party",
				ActorUuid: uuid.New().String(),
				RoleId:    "poam-manager",
			},
			{
				Type:      "tool",
				ActorUuid: uuid.New().String(),
			},
		},
	}
	inputJson, err := json.Marshal(osc)
	assert.NoError(t, err)

	poamOrigin := &PoamItemOrigin{}
	poamOrigin.UnmarshalOscal(osc)
	output := poamOrigin.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)

	assert.JSONEq(t, string(inputJson), string(outputJson))
}
