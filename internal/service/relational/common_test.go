package relational

import (
	"encoding/json"
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTelephoneNumber_OscalMarshalling(t *testing.T) {
	oscalTN := oscaltypes113.TelephoneNumber{
		Type:   "mobile",
		Number: "12345",
	}
	inputJson, err := json.Marshal(oscalTN)
	assert.NoError(t, err)

	tn := &TelephoneNumber{}
	tn.UnmarshalOscal(oscalTN)
	output := tn.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestAddress_OscalMarshalling(t *testing.T) {
	oscalAddr := oscaltypes113.Address{
		Type:       "home",
		AddrLines:  &[]string{"line1", "line2"},
		City:       "TestCity",
		State:      "TestState",
		PostalCode: "12345",
		Country:    "TestCountry",
	}
	inputJson, err := json.Marshal(oscalAddr)
	assert.NoError(t, err)

	a := &Address{}
	a.UnmarshalOscal(oscalAddr)
	output := a.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestDocumentID_OscalMarshalling(t *testing.T) {
	oscalID := oscaltypes113.DocumentId{
		Scheme:     "http://www.doi.org/",
		Identifier: "id123",
	}
	inputJson, err := json.Marshal(oscalID)
	assert.NoError(t, err)

	d := &DocumentID{}
	d.UnmarshalOscal(oscalID)
	output := d.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestResponsibleParty_OscalMarshalling(t *testing.T) {
	oscalRP := oscaltypes113.ResponsibleParty{
		Remarks: "example remarks",
		RoleId:  "role-id",
		Props: &[]oscaltypes113.Property{
			{
				Class:   "pc",
				Group:   "pg",
				Name:    "pn",
				Ns:      "pns",
				Remarks: "pr",
				UUID:    uuid.New().String(),
				Value:   "pv",
			},
		},
		Links: &[]oscaltypes113.Link{
			{
				Href:      "h1",
				MediaType: "m1",
				Text:      "t1",
			},
		},
		PartyUuids: []string{uuid.New().String(), uuid.New().String()},
	}
	inputJson, err := json.Marshal(oscalRP)
	assert.NoError(t, err)

	rp := &ResponsibleParty{}
	rp.UnmarshalOscal(oscalRP)
	output := rp.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}
