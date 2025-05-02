package relational

import (
	"encoding/json"
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestPart_OscalMarshalling(t *testing.T) {
	oscalPart := oscaltypes113.Part{
		ID:    "a id",
		Ns:    "a ns",
		Name:  "a name",
		Title: "a title",
		Class: "a class",
		Prose: "some prose",
		Links: &[]oscaltypes113.Link{
			{
				Href:      "http://one",
				MediaType: "related",
				Text:      "One Link",
			},
			{
				Href:      "http://two",
				MediaType: "related",
				Text:      "Two Link",
			},
		},
		Parts: &[]oscaltypes113.Part{
			{
				ID:    "sub id",
				Ns:    "sub ns",
				Name:  "sub name",
				Title: "sub title",
				Class: "sub class",
				Prose: "some sub prose",
				Links: &[]oscaltypes113.Link{
					{
						Href:      "http://one",
						MediaType: "related",
						Text:      "One Link",
					},
					{
						Href:      "http://two",
						MediaType: "related",
						Text:      "Two Link",
					},
				},
				Props: &[]oscaltypes113.Property{
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
			},
		},
		Props: &[]oscaltypes113.Property{
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
	}
	inputJson, err := json.Marshal(oscalPart)

	// Marshal and Unmarshal, and make sure it remains exactly the same
	part := &Part{}
	part.UnmarshalOscal(oscalPart)
	output := part.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestParameterConstraintTest_OscalMarshalling(t *testing.T) {
	oscalTest := oscaltypes113.ConstraintTest{
		Expression: "example expression",
		Remarks:    "example remarks",
	}
	inputJson, err := json.Marshal(oscalTest)
	assert.NoError(t, err)

	pct := &ParameterConstraintTest{}
	pct.UnmarshalOscal(oscalTest)
	output := pct.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestParameterConstraint_OscalMarshalling(t *testing.T) {
	oscalConstraint := oscaltypes113.ParameterConstraint{
		Description: "example description",
		Tests: &[]oscaltypes113.ConstraintTest{
			{
				Expression: "expr1",
				Remarks:    "rem1",
			},
			{
				Expression: "expr2",
				Remarks:    "rem2",
			},
		},
	}
	inputJson, err := json.Marshal(oscalConstraint)
	assert.NoError(t, err)

	pc := &ParameterConstraint{}
	pc.UnmarshalOscal(oscalConstraint)
	output := pc.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestParameterGuideline_OscalMarshalling(t *testing.T) {
	oscalGuideline := oscaltypes113.ParameterGuideline{
		Prose: "example prose",
	}
	inputJson, err := json.Marshal(oscalGuideline)
	assert.NoError(t, err)

	pg := &ParameterGuideline{}
	pg.UnmarshalOscal(oscalGuideline)
	output := pg.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestParameterSelection_OscalMarshalling(t *testing.T) {
	oscalSel := oscaltypes113.ParameterSelection{
		HowMany: "one-or-more",
		Choice:  &[]string{"opt1", "opt2"},
	}
	inputJson, err := json.Marshal(oscalSel)
	assert.NoError(t, err)

	ps := &ParameterSelection{}
	ps.UnmarshalOscal(oscalSel)
	output := ps.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestParameter_OscalMarshalling(t *testing.T) {
	oscalParam := oscaltypes113.Parameter{
		ID:      "param-id",
		Class:   "param-class",
		Label:   "param-label",
		Usage:   "param-usage",
		Remarks: "param-remarks",
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
		Select: &oscaltypes113.ParameterSelection{
			HowMany: "one",
			Choice:  &[]string{"opt"},
		},
		Constraints: &[]oscaltypes113.ParameterConstraint{
			{
				Description: "desc",
				Tests: &[]oscaltypes113.ConstraintTest{
					{
						Expression: "expr",
						Remarks:    "rem",
					},
				},
			},
		},
		Guidelines: &[]oscaltypes113.ParameterGuideline{
			{
				Prose: "gprose",
			},
		},
		Values: &[]string{"v1", "v2"},
	}
	inputJson, err := json.Marshal(oscalParam)
	assert.NoError(t, err)

	p := &Parameter{}
	p.UnmarshalOscal(oscalParam)
	output := p.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestControl_OscalMarshalling(t *testing.T) {
	// Prepare a minimal OSCAL Control with Props and Links
	oscalCtrl := oscaltypes113.Control{
		ID:    "ctrl-id",
		Title: "ctrl-title",
		Class: "ctrl-class",
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
				Text:      "link-text",
			},
		},
	}
	inputJson, err := json.Marshal(oscalCtrl)
	assert.NoError(t, err)

	// Unmarshal into relational.Control and marshal back
	id := uuid.New()
	ctrl := &Control{}
	ctrl.UnmarshalOscal(oscalCtrl, id)
	output := ctrl.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestGroup_OscalMarshalling(t *testing.T) {
	oscalGroup := oscaltypes113.Group{
		ID:    "group-id",
		Title: "group-title",
		Class: "group-class",
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
				Text:      "link-text",
			},
		},
	}
	inputJson, err := json.Marshal(oscalGroup)
	assert.NoError(t, err)

	grp := &Group{}
	// Use a random UUID for the catalogId parameter
	grp.UnmarshalOscal(oscalGroup, uuid.New())
	output := grp.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestCatalog_OscalMarshalling(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		oscalCat := oscaltypes113.Catalog{
			UUID: uuid.New().String(),
			Metadata: oscaltypes113.Metadata{
				Title:        "catalog title",
				Published:    &now,
				LastModified: now,
				Version:      "v1",
				OscalVersion: "1.1.3",
				Remarks:      "catalog remarks",
			},
			Groups: &[]oscaltypes113.Group{
				{
					Class: "family",
					Controls: &[]oscaltypes113.Control{
						{
							ID:    "AC-1",
							Class: "SP800-53",
							Title: "Access Control",
						},
					},
					ID:    "AC",
					Title: "",
				},
			},
		}
		inputJson, err := json.Marshal(oscalCat)
		assert.NoError(t, err)

		c := &Catalog{}
		c.UnmarshalOscal(oscalCat)
		output := c.MarshalOscal()
		outputJson, err := json.Marshal(output)
		assert.NoError(t, err)
		assert.JSONEq(t, string(inputJson), string(outputJson))
	})

	t.Run("SP800-53", func(t *testing.T) {
		// SP800-53 ensures that a FULL catalog can be unmarshalled, and re-marshalled, producing the same JSON object.
		// This proves our entire schema for a Catalog works correctly.
		f, err := os.Open("./testdata/full_catalog.json")
		assert.NoError(t, err)
		defer f.Close()

		embed := struct {
			Catalog oscaltypes113.Catalog `json:"catalog"`
		}{}
		err = json.NewDecoder(f).Decode(&embed)
		assert.NoError(t, err)

		inputJson, err := json.Marshal(embed.Catalog)
		assert.NoError(t, err)

		catalog := &Catalog{}
		// Use a random UUID for the catalogId parameter
		catalog.UnmarshalOscal(embed.Catalog)
		output := catalog.MarshalOscal()
		outputJson, err := json.Marshal(output)
		assert.NoError(t, err)
		assert.JSONEq(t, string(inputJson), string(outputJson))
	})
}
