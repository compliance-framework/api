package relational

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/datatypes"
)

func TestSatisfiedControlImplementationResponsibilityUnmarshal(t *testing.T) {
	data := oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility{
		UUID:               uuid.New().String(),
		ResponsibilityUuid: uuid.New().String(),
		Description:        "Test description",
		Remarks:            "Test remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Class:   "prop class",
				Group:   "prop group",
				Name:    "prop name",
				Ns:      "prop ns",
				Remarks: "prop remarks",
				UUID:    uuid.New().String(),
				Value:   "prop value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "http://one",
				MediaType: "related",
				Text:      "One Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:     "role-1",
				Remarks:    "Test role remarks",
				PartyUuids: &[]string{uuid.New().String()},
				Links: &[]oscalTypes_1_1_3.Link{
					{
						Href:      "http://role-link",
						MediaType: "application/json",
						Text:      "Role Link",
					},
				},
				Props: &[]oscalTypes_1_1_3.Property{
					{
						Name:  "role-prop-name",
						Value: "role-prop-value",
					},
				},
			},
		},
	}

	inputJson, err := json.Marshal(data)
	assert.NoError(t, err)

	ci := &SatisfiedControlImplementationResponsibility{}
	ci.UnmarshalOscal(data)
	output := ci.MarshalOscal()
	outputJson, err := json.Marshal(output)

	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestControlImplementationResponsibilityUnmarshal(t *testing.T) {
	data := oscalTypes_1_1_3.ControlImplementationResponsibility{
		UUID:         uuid.New().String(),
		ProvidedUuid: uuid.New().String(),
		Description:  "Test description",
		Remarks:      "Test remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Class:   "prop class",
				Group:   "prop group",
				Name:    "prop name",
				Ns:      "prop ns",
				Remarks: "prop remarks",
				UUID:    uuid.New().String(),
				Value:   "prop value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "http://one",
				MediaType: "related",
				Text:      "One Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:     "role-1",
				Remarks:    "Test role remarks",
				PartyUuids: &[]string{uuid.New().String()},
			},
		},
	}

	inputJson, err := json.Marshal(data)
	assert.NoError(t, err)

	ci := &ControlImplementationResponsibility{}
	ci.UnmarshalOscal(data)
	output := ci.MarshalOscal()
	outputJson, err := json.Marshal(output)

	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestInheritedControlImplementationUnmarshal(t *testing.T) {
	data := oscalTypes_1_1_3.InheritedControlImplementation{
		UUID:         uuid.New().String(),
		ProvidedUuid: uuid.New().String(),
		Description:  "Test description",
		Props: &[]oscalTypes_1_1_3.Property{
			{
				Class:   "prop class",
				Group:   "prop group",
				Name:    "prop name",
				Ns:      "prop ns",
				Remarks: "prop remarks",
				UUID:    uuid.New().String(),
				Value:   "prop value",
			},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{
				Href:      "http://one",
				MediaType: "related",
				Text:      "One Link",
			},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{
				RoleId:     "role-1",
				Remarks:    "Test role remarks",
				PartyUuids: &[]string{uuid.New().String()},
				Links: &[]oscalTypes_1_1_3.Link{
					{
						Href:      "http://role-link",
						MediaType: "application/json",
						Text:      "Role Link",
					},
				},
				Props: &[]oscalTypes_1_1_3.Property{
					{
						Name:  "role-prop-name",
						Value: "role-prop-value",
					},
				},
			},
		},
	}

	inputJson, err := json.Marshal(data)
	assert.NoError(t, err)

	ici := &InheritedControlImplementation{}
	ici.UnmarshalOscal(data)
	output := ici.MarshalOscal()
	outputJson, err := json.Marshal(output)

	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestStatement_OscalMarshalling(t *testing.T) {
	oscalStmt := oscalTypes_1_1_3.Statement{
		UUID:        uuid.New().String(),
		StatementId: "stmt-1",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "prop1", Value: "val1"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "http://link", MediaType: "mt", Text: "text"},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{RoleId: "role-1", Remarks: "r1"},
		},
		Remarks: "remarks1",
	}
	inputJson, err := json.Marshal(oscalStmt)
	assert.NoError(t, err)

	stmt := &Statement{}
	stmt.UnmarshalOscal(oscalStmt)
	output := stmt.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestExport_OscalMarshalling(t *testing.T) {
	oscalExp := oscalTypes_1_1_3.Export{
		Description: "exp-desc",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		Remarks: "exp-remarks",
		Provided: &[]oscalTypes_1_1_3.ProvidedControlImplementation{
			{
				UUID:        uuid.New().String(),
				Description: "prov-desc",
			},
		},
		Responsibilities: &[]oscalTypes_1_1_3.ControlImplementationResponsibility{
			{
				UUID:        uuid.New().String(),
				Description: "res-desc",
			},
		},
	}
	inputJson, err := json.Marshal(oscalExp)
	assert.NoError(t, err)

	exp := &Export{}
	exp.UnmarshalOscal(oscalExp)
	output := exp.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestByComponent_OscalMarshalling(t *testing.T) {
	oscalBC := oscalTypes_1_1_3.ByComponent{
		UUID:          uuid.New().String(),
		ComponentUuid: uuid.New().String(),
		Description:   "comp-desc",
		Remarks:       "bc-remarks",
	}
	inputJson, err := json.Marshal(oscalBC)
	assert.NoError(t, err)

	bc := &ByComponent{}
	bc.UnmarshalOscal(oscalBC)
	output := bc.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestImplementedRequirement_OscalMarshalling(t *testing.T) {
	oscalReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "ctrl-1",
		Remarks:   "req-remarks",
	}
	inputJson, err := json.Marshal(oscalReq)
	assert.NoError(t, err)

	ir := &ImplementedRequirement{}
	ir.UnmarshalOscal(oscalReq)
	output := ir.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestControlImplementation_OscalMarshalling(t *testing.T) {
	oscalCI := oscalTypes_1_1_3.ControlImplementation{
		Description: "ci-desc",
		SetParameters: &[]oscalTypes_1_1_3.SetParameter{
			{ParamId: "param-name", Values: []string{"param-value"}},
		},
		ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
			{
				UUID:      uuid.New().String(),
				ControlId: "ctrl-1",
				Remarks:   "req-remarks",
			},
		},
	}
	inputJson, err := json.Marshal(oscalCI)
	assert.NoError(t, err)

	ci := &ControlImplementation{}
	ci.UnmarshalOscal(oscalCI)
	output := ci.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestDiagram_OscalMarshalling(t *testing.T) {
	oscalDiag := oscalTypes_1_1_3.Diagram{
		UUID:        uuid.New().String(),
		Description: "desc",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		Caption: "cap",
		Remarks: "rem",
	}
	inputJson, err := json.Marshal(oscalDiag)
	assert.NoError(t, err)

	d := &Diagram{}
	d.UnmarshalOscal(oscalDiag)
	output := d.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestDataFlow_OscalMarshalling(t *testing.T) {
	oscalDF := oscalTypes_1_1_3.DataFlow{
		Description: "desc",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		Remarks: "rem",
		Diagrams: &[]oscalTypes_1_1_3.Diagram{
			{
				UUID:        uuid.New().String(),
				Description: "diagram-desc",
				Caption:     "cap",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "dp", Value: "dv"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "dh", MediaType: "dm", Text: "dt"},
				},
				Remarks: "drem",
			},
		},
	}
	inputJson, err := json.Marshal(oscalDF)
	assert.NoError(t, err)

	df := &DataFlow{}
	df.UnmarshalOscal(oscalDF)
	output := df.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestNetworkArchitecture_OscalMarshalling(t *testing.T) {
	oscalDF := oscalTypes_1_1_3.NetworkArchitecture{
		Description: "desc",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		Remarks: "rem",
		Diagrams: &[]oscalTypes_1_1_3.Diagram{
			{
				UUID:        uuid.New().String(),
				Description: "diagram-desc",
				Caption:     "cap",
				Props: &[]oscalTypes_1_1_3.Property{
					{Name: "dp", Value: "dv"},
				},
				Links: &[]oscalTypes_1_1_3.Link{
					{Href: "dh", MediaType: "dm", Text: "dt"},
				},
				Remarks: "drem",
			},
		},
	}
	inputJson, err := json.Marshal(oscalDF)
	assert.NoError(t, err)

	df := &NetworkArchitecture{}
	df.UnmarshalOscal(oscalDF)
	output := df.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestAuthorizationBoundary_OscalMarshalling(t *testing.T) {
	oscalAB := oscalTypes_1_1_3.AuthorizationBoundary{
		Description: "ab-desc",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		Remarks: "ab-rem",
		Diagrams: &[]oscalTypes_1_1_3.Diagram{
			{
				UUID:        uuid.New().String(),
				Description: "diag-desc",
				Caption:     "cap",
				Remarks:     "diag-rem",
			},
		},
	}
	inputJson, err := json.Marshal(oscalAB)
	assert.NoError(t, err)

	ab := &AuthorizationBoundary{}
	ab.UnmarshalOscal(oscalAB)
	output := ab.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestSystemInformation_OscalMarshalling(t *testing.T) {
	oscalSI := oscalTypes_1_1_3.SystemInformation{
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		InformationTypes: []oscalTypes_1_1_3.InformationType{
			{
				UUID:        uuid.New().String(),
				Title:       "title",
				Description: "desc",
			},
		},
	}
	inputJson, err := json.Marshal(oscalSI)
	assert.NoError(t, err)

	si := &SystemInformation{}
	si.UnmarshalOscal(oscalSI)
	output := si.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestLeveragedAuthorization_OscalMarshalling(t *testing.T) {
	now := time.Now().UTC()
	dateStr := now.Format(time.DateOnly)
	oscalLA := oscalTypes_1_1_3.LeveragedAuthorization{
		UUID:           uuid.New().String(),
		Title:          "LA Title",
		PartyUuid:      uuid.New().String(),
		DateAuthorized: dateStr,
		Remarks:        "la-remarks",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
	}
	inputJson, err := json.Marshal(oscalLA)
	assert.NoError(t, err)

	la := &LeveragedAuthorization{}
	la.UnmarshalOscal(oscalLA)
	output := la.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestAuthorizedPrivilege_OscalMarshalling(t *testing.T) {
	oscalAP := oscalTypes_1_1_3.AuthorizedPrivilege{
		Title:              "AP Title",
		Description:        "ap-desc",
		FunctionsPerformed: []string{"f1", "f2"},
	}
	inputJson, err := json.Marshal(oscalAP)
	assert.NoError(t, err)

	ap := &AuthorizedPrivilege{}
	ap.UnmarshalOscal(oscalAP)
	output := ap.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestSystemUser_OscalMarshalling(t *testing.T) {
	oscalSU := oscalTypes_1_1_3.SystemUser{
		UUID:        uuid.New().String(),
		Title:       "User Title",
		ShortName:   "usr",
		Description: "user-desc",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p", Value: "v"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		RoleIds:              &[]string{"r1", "r2"},
		AuthorizedPrivileges: &[]oscalTypes_1_1_3.AuthorizedPrivilege{{Title: "AP", Description: "apd", FunctionsPerformed: []string{"f"}}},
	}
	inputJson, err := json.Marshal(oscalSU)
	assert.NoError(t, err)

	su := &SystemUser{}
	su.UnmarshalOscal(oscalSU)
	output := su.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestSystemComponent_OscalMarshalling(t *testing.T) {
	oscalSC := oscalTypes_1_1_3.SystemComponent{
		UUID:        uuid.New().String(),
		Type:        "type1",
		Title:       "title1",
		Description: "desc1",
		Purpose:     "purpose1",
		Status: oscalTypes_1_1_3.SystemComponentStatus{
			State: "active",
		},
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p1", Value: "v1"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "http://link", MediaType: "mt", Text: "text"},
		},
		ResponsibleRoles: &[]oscalTypes_1_1_3.ResponsibleRole{
			{RoleId: "role1", Remarks: "rr"},
		},
		Protocols: &[]oscalTypes_1_1_3.Protocol{
			{Name: "proto", PortRanges: &[]oscalTypes_1_1_3.PortRange{
				{
					Start: 443,
					End:   443,
				},
			}},
		},
		Remarks: "rem1",
	}
	inputJson, err := json.Marshal(oscalSC)
	assert.NoError(t, err)

	sc := &SystemComponent{}
	sc.UnmarshalOscal(oscalSC)
	output := sc.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestInformationType_OscalMarshalling(t *testing.T) {
	oscalIT := oscalTypes_1_1_3.InformationType{
		UUID:        uuid.New().String(),
		Title:       "Test Title",
		Description: "Test Description",
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "p1", Value: "v1"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "http://link", MediaType: "mt", Text: "text"},
		},
		ConfidentialityImpact: &oscalTypes_1_1_3.Impact{
			Base: "impact",
		},
		IntegrityImpact: &oscalTypes_1_1_3.Impact{
			Base: "impact",
		},
		AvailabilityImpact: &oscalTypes_1_1_3.Impact{
			Base: "impact",
		},
		Categorizations: &[]oscalTypes_1_1_3.InformationTypeCategorization{
			{},
		},
	}
	inputJson, err := json.Marshal(oscalIT)
	assert.NoError(t, err)

	it := &InformationType{}
	it.UnmarshalOscal(oscalIT)
	output := it.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestSystemCharacteristics_OscalMarshalling(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dateStr := now.Format(time.DateOnly)
	oscalSC := oscalTypes_1_1_3.SystemCharacteristics{
		SystemName:               "name",
		SystemNameShort:          "short",
		Description:              "desc",
		DateAuthorized:           dateStr,
		SecuritySensitivityLevel: "level",
		Remarks:                  "rem",
		SystemIds: []oscalTypes_1_1_3.SystemId{
			{ID: "id", IdentifierType: "some-type"},
		},
		SystemInformation: oscalTypes_1_1_3.SystemInformation{
			Links:            nil,
			InformationTypes: nil,
		},
		Status: oscalTypes_1_1_3.Status{
			State: "active",
		},
		AuthorizationBoundary: oscalTypes_1_1_3.AuthorizationBoundary{
			Description: "ab-desc",
			Remarks:     "ab-rem",
		},
		NetworkArchitecture: &oscalTypes_1_1_3.NetworkArchitecture{
			Description: "na-desc",
			Remarks:     "na-rem",
		},
		DataFlow: &oscalTypes_1_1_3.DataFlow{
			Description: "df-desc",
			Remarks:     "df-rem",
		},
		Props: &[]oscalTypes_1_1_3.Property{
			{Name: "pn", Value: "pv"},
		},
		Links: &[]oscalTypes_1_1_3.Link{
			{Href: "h", MediaType: "m", Text: "t"},
		},
		ResponsibleParties: &[]oscalTypes_1_1_3.ResponsibleParty{
			{RoleId: "r", Remarks: "rr"},
		},
	}
	inputJson, err := json.Marshal(oscalSC)
	assert.NoError(t, err)

	sc := &SystemCharacteristics{}
	sc.UnmarshalOscal(oscalSC)
	output := sc.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestSystemSecurityPlan_OscalMarshalling(t *testing.T) {
	t.Run("Full FedRamp SSP", func(t *testing.T) {
		// SP800-53 ensures that a FULL catalog can be unmarshalled, and re-marshalled, producing the same JSON object.
		// This proves our entire schema for a Catalog works correctly.
		f, err := os.Open("./testdata/full_ssp.json")
		assert.NoError(t, err)
		defer func() {
			err := f.Close()
			if err != nil {
				t.Logf("failed to close SSP test file: %v", err)
			}
		}()

		embed := struct {
			SSP oscalTypes_1_1_3.SystemSecurityPlan `json:"system-security-plan"`
		}{}
		err = json.NewDecoder(f).Decode(&embed)
		assert.NoError(t, err)

		inputJson, err := json.Marshal(embed.SSP)
		assert.NoError(t, err)

		ssp := &SystemSecurityPlan{}
		// Use a random UUID for the catalogId parameter
		ssp.UnmarshalOscal(embed.SSP)
		output := ssp.MarshalOscal()
		outputJson, err := json.Marshal(output)
		assert.NoError(t, err)
		assert.JSONEq(t, string(inputJson), string(outputJson))
	})
}

func TestImplementationStatusState_Valid(t *testing.T) {
	validStates := []ImplementationStatusState{
		ImplementationStatusImplemented,
		ImplementationStatusPartial,
		ImplementationStatusPlanned,
		ImplementationStatusAlternative,
		ImplementationStatusNotApplicable,
	}
	for _, state := range validStates {
		t.Run(string(state), func(t *testing.T) {
			assert.True(t, IsValidImplementationStatusState(state))
		})
	}
}

func TestImplementationStatusState_Invalid(t *testing.T) {
	invalidStates := []ImplementationStatusState{
		"invalid",
		"IMPLEMENTED",
		"Implemented",
		"Partial",
		"unknown",
		"",
	}
	for _, state := range invalidStates {
		name := string(state)
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			assert.False(t, IsValidImplementationStatusState(state))
		})
	}
}

func TestImplementationStatus_Validate(t *testing.T) {
	t.Run("valid states pass validation", func(t *testing.T) {
		for _, state := range ValidImplementationStatusStates() {
			is := &ImplementationStatus{State: state}
			assert.NoError(t, is.Validate(), "state %q should be valid", state)
		}
	})

	t.Run("invalid state returns error", func(t *testing.T) {
		is := &ImplementationStatus{State: "bogus"}
		err := is.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid implementation status state")
		assert.Contains(t, err.Error(), "bogus")
	})

	t.Run("empty state returns error", func(t *testing.T) {
		is := &ImplementationStatus{State: ""}
		err := is.Validate()
		assert.Error(t, err)
	})
}

func TestImplementationStatus_UnmarshalOscal(t *testing.T) {
	oscalIS := oscalTypes_1_1_3.ImplementationStatus{
		State:   "partial",
		Remarks: "Partial implementation in progress",
	}
	is := &ImplementationStatus{}
	is.UnmarshalOscal(oscalIS)

	assert.Equal(t, ImplementationStatusPartial, is.State)
	assert.Equal(t, "Partial implementation in progress", is.Remarks)
}

func TestImplementationStatus_MarshalOscal(t *testing.T) {
	is := &ImplementationStatus{
		State:   ImplementationStatusPlanned,
		Remarks: "Plan documented in remarks",
	}
	oscalIS := is.MarshalOscal()
	assert.Equal(t, "planned", oscalIS.State)
	assert.Equal(t, "Plan documented in remarks", oscalIS.Remarks)
}

func TestConvertOscalToImplementationStatus(t *testing.T) {
	oscalIS := &oscalTypes_1_1_3.ImplementationStatus{
		State:   "alternative",
		Remarks: "Alternative approach taken",
	}
	result := ConvertOscalToImplementationStatus(oscalIS)
	assert.Equal(t, ImplementationStatusAlternative, result.Data().State)
	assert.Equal(t, "Alternative approach taken", result.Data().Remarks)
}

func TestConvertImplementationStatusToOscal(t *testing.T) {
	is := ImplementationStatus{
		State:   ImplementationStatusNotApplicable,
		Remarks: "Not applicable for this system",
	}
	data := datatypes.NewJSONType(is)
	oscalIS := ConvertImplementationStatusToOscal(data)
	assert.Equal(t, "not-applicable", oscalIS.State)
	assert.Equal(t, "Not applicable for this system", oscalIS.Remarks)
}

func TestImplementationStatus_JSONRoundTrip(t *testing.T) {
	is := ImplementationStatus{
		State:   ImplementationStatusImplemented,
		Remarks: "Fully implemented",
	}
	b, err := json.Marshal(is)
	assert.NoError(t, err)

	var parsed ImplementationStatus
	err = json.Unmarshal(b, &parsed)
	assert.NoError(t, err)
	assert.Equal(t, is.State, parsed.State)
	assert.Equal(t, is.Remarks, parsed.Remarks)
}

func TestImplementationStatus_JSONCompatibleWithOscal(t *testing.T) {
	oscalJSON := `{"state":"implemented","remarks":"Test remarks"}`

	var is ImplementationStatus
	err := json.Unmarshal([]byte(oscalJSON), &is)
	assert.NoError(t, err)
	assert.Equal(t, ImplementationStatusImplemented, is.State)
	assert.Equal(t, "Test remarks", is.Remarks)

	b, err := json.Marshal(is)
	assert.NoError(t, err)
	assert.JSONEq(t, oscalJSON, string(b))
}

func TestImplementationStatus_OmittedStatus(t *testing.T) {
	id := uuid.New()
	bc := ByComponent{
		UUIDModel:     UUIDModel{ID: &id},
		ComponentUUID: uuid.New(),
		Description:   "Test component",
	}
	oscalBC := bc.MarshalOscal()
	assert.Nil(t, oscalBC.ImplementationStatus)
}

func TestByComponent_WithImplementationStatus_RoundTrip(t *testing.T) {
	compUUID := uuid.New()
	bcUUID := uuid.New()
	oscalBC := oscalTypes_1_1_3.ByComponent{
		UUID:          bcUUID.String(),
		ComponentUuid: compUUID.String(),
		Description:   "Test by-component",
		ImplementationStatus: &oscalTypes_1_1_3.ImplementationStatus{
			State:   "partial",
			Remarks: "Partially done",
		},
	}

	relBC := &ByComponent{}
	relBC.UnmarshalOscal(oscalBC)

	assert.Equal(t, ImplementationStatusPartial, relBC.ImplementationStatus.Data().State)
	assert.Equal(t, "Partially done", relBC.ImplementationStatus.Data().Remarks)

	// Validate passes
	is := relBC.ImplementationStatus.Data()
	assert.NoError(t, is.Validate())

	// Marshal back to OSCAL
	out := relBC.MarshalOscal()
	assert.NotNil(t, out.ImplementationStatus)
	assert.Equal(t, "partial", out.ImplementationStatus.State)
	assert.Equal(t, "Partially done", out.ImplementationStatus.Remarks)
}

func TestValidImplementationStatusStates_ReturnsAllStates(t *testing.T) {
	states := ValidImplementationStatusStates()
	assert.Len(t, states, 5)
	expected := map[ImplementationStatusState]bool{
		ImplementationStatusImplemented:   true,
		ImplementationStatusPartial:       true,
		ImplementationStatusPlanned:       true,
		ImplementationStatusAlternative:   true,
		ImplementationStatusNotApplicable: true,
	}
	for _, s := range states {
		assert.True(t, expected[s], "unexpected state %q", s)
	}
}
