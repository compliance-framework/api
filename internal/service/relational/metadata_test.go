package relational

import (
	"encoding/json"
	"testing"
	"time"

	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRole_OscalMarshalling(t *testing.T) {
	oscalRole := oscaltypes113.Role{
		ID:          "role-id",
		Title:       "role-title",
		ShortName:   "rshort",
		Description: "rdesc",
		Remarks:     "rremarks",
	}
	// add a prop and link
	oscalRole.Props = &[]oscaltypes113.Property{
		{
			Class:   "pc",
			Group:   "pg",
			Name:    "pn",
			Ns:      "pns",
			Remarks: "pr",
			UUID:    uuid.New().String(),
			Value:   "pv",
		},
	}
	oscalRole.Links = &[]oscaltypes113.Link{
		{
			Href:      "http://link",
			MediaType: "mt",
			Text:      "txt",
		},
	}
	inputJson, err := json.Marshal(oscalRole)
	assert.NoError(t, err)

	r := &Role{}
	r.UnmarshalOscal(oscalRole)
	output := r.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestLocation_OscalMarshalling(t *testing.T) {
	oscalLoc := oscaltypes113.Location{
		UUID:           uuid.New().String(),
		EmailAddresses: &[]string{"email@example.com"},
		TelephoneNumbers: &[]oscaltypes113.TelephoneNumber{
			{Type: "mobile", Number: "12345"},
		},
		Urls: &[]string{"http://example.com"},
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
				Href:      "http://link",
				MediaType: "mt",
				Text:      "txt",
			},
		},
		Remarks: "location remarks",
	}
	inputJson, err := json.Marshal(oscalLoc)
	assert.NoError(t, err)

	loc := &Location{}
	loc.UnmarshalOscal(oscalLoc)
	output := loc.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestRevision_OscalMarshalling(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oscalRev := oscaltypes113.RevisionHistoryEntry{
		Title:        "rev-title",
		Published:    &now,
		LastModified: &now,
		Version:      "v1",
		OscalVersion: "1.1.3",
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
				Href:      "http://link",
				MediaType: "mt",
				Text:      "txt",
			},
		},
		Remarks: "rev-remarks",
	}
	inputJson, err := json.Marshal(oscalRev)
	assert.NoError(t, err)

	r := &Revision{}
	r.UnmarshalOscal(oscalRev)
	output := r.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestPartyExternalID_OscalMarshalling(t *testing.T) {
	oscalPEI := oscaltypes113.PartyExternalIdentifier{
		ID:     "id123",
		Scheme: "http://orcid.org/",
	}
	inputJson, err := json.Marshal(oscalPEI)
	assert.NoError(t, err)

	pei := &PartyExternalID{}
	pei.UnmarshalOscal(oscalPEI)
	output := pei.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestParty_OscalMarshalling(t *testing.T) {
	oscalParty := oscaltypes113.Party{
		UUID:             uuid.New().String(),
		Type:             "person",
		Name:             "TestName",
		ShortName:        "TestShort",
		ExternalIds:      &[]oscaltypes113.PartyExternalIdentifier{{ID: "eid", Scheme: "http://orcid.org/"}},
		Props:            &[]oscaltypes113.Property{{Class: "pc", Group: "pg", Name: "pn", Ns: "pns", Remarks: "pr", UUID: uuid.New().String(), Value: "pv"}},
		Links:            &[]oscaltypes113.Link{{Href: "http://link", MediaType: "mt", Text: "txt"}},
		EmailAddresses:   &[]string{"e1", "e2"},
		TelephoneNumbers: &[]oscaltypes113.TelephoneNumber{{Type: "mobile", Number: "12345"}},
		Addresses:        &[]oscaltypes113.Address{{Type: "home", AddrLines: &[]string{"l1"}, City: "city", State: "state", PostalCode: "pc", Country: "country"}},
		Remarks:          "remarks",
	}
	inputJson, err := json.Marshal(oscalParty)
	assert.NoError(t, err)

	p := &Party{}
	p.UnmarshalOscal(oscalParty)
	output := p.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestAction_OscalMarshalling(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oscalAct := oscaltypes113.Action{
		UUID:    uuid.New().String(),
		Date:    &now,
		Type:    "type1",
		System:  "system1",
		Remarks: "remarks1",
	}
	inputJson, err := json.Marshal(oscalAct)
	assert.NoError(t, err)

	act := &Action{}
	act.UnmarshalOscal(oscalAct)
	output := act.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestMetadata_OscalMarshalling(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oscalMD := oscaltypes113.Metadata{
		Title:        "mtitle",
		Published:    &now,
		LastModified: now,
		Version:      "v1",
		OscalVersion: "1.1.3",
		Remarks:      "mremarks",
		DocumentIds: &[]oscaltypes113.DocumentId{
			{Scheme: "http://www.doi.org/", Identifier: "doc1"},
		},
		Props: &[]oscaltypes113.Property{
			{Class: "pc", Group: "pg", Name: "pn", Ns: "pns", Remarks: "pr", UUID: uuid.New().String(), Value: "pv"},
		},
		Links: &[]oscaltypes113.Link{
			{Href: "http://link", MediaType: "mt", Text: "txt"},
		},
		Revisions: &[]oscaltypes113.RevisionHistoryEntry{
			{Version: "rv1", Title: "rev1", Remarks: "rpr", OscalVersion: "1.1.3", Published: &now, LastModified: &now},
		},
		Roles: &[]oscaltypes113.Role{
			{ID: "role1", Title: "roleTitle", ShortName: "rsh", Description: "rdesc", Remarks: "rpr"},
		},
		Locations: &[]oscaltypes113.Location{
			{UUID: uuid.New().String(), EmailAddresses: &[]string{"e1"}, TelephoneNumbers: &[]oscaltypes113.TelephoneNumber{{Type: "mobile", Number: "123"}}, Urls: &[]string{"http://u"}, Remarks: "locremarks"},
		},
		Parties: &[]oscaltypes113.Party{
			{UUID: uuid.New().String(), Type: "person", Name: "name", ShortName: "sn", Remarks: "pr"},
		},
		ResponsibleParties: &[]oscaltypes113.ResponsibleParty{
			{RoleId: "role1", Remarks: "rpr"},
		},
		Actions: &[]oscaltypes113.Action{
			{UUID: uuid.New().String(), Date: &now, Type: "atype", System: "asys", Remarks: "arm"},
		},
	}
	inputJson, err := json.Marshal(oscalMD)
	assert.NoError(t, err)

	md := &Metadata{}
	md.UnmarshalOscal(oscalMD)
	output := md.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}
