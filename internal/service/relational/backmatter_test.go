package relational

import (
	"encoding/json"
	"testing"

	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestBase64_OscalMarshalling(t *testing.T) {
	oscalBase := oscaltypes113.Base64{
		Filename:  "file.txt",
		MediaType: "text/plain",
		Value:     "dGVzdC12YWx1ZQ==",
	}
	inputJson, err := json.Marshal(oscalBase)
	assert.NoError(t, err)

	b := &Base64{}
	b.UnmarshalOscal(oscalBase)
	output := b.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestHash_OscalMarshalling(t *testing.T) {
	oscalHash := oscaltypes113.Hash{
		Algorithm: "SHA-256",
		Value:     "abc123",
	}
	inputJson, err := json.Marshal(oscalHash)
	assert.NoError(t, err)

	h := &Hash{}
	h.UnmarshalOscal(oscalHash)
	output := h.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestResourceLink_OscalMarshalling(t *testing.T) {
	oscalRL := oscaltypes113.ResourceLink{
		Href:      "http://example.com",
		MediaType: "application/pdf",
		Hashes: &[]oscaltypes113.Hash{
			{
				Algorithm: "SHA-256",
				Value:     "def456",
			},
		},
	}
	inputJson, err := json.Marshal(oscalRL)
	assert.NoError(t, err)

	rl := &ResourceLink{}
	rl.UnmarshalOscal(oscalRL)
	output := rl.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestCitation_OscalMarshalling(t *testing.T) {
	oscalCit := oscaltypes113.Citation{
		Text: "example citation",
	}
	inputJson, err := json.Marshal(oscalCit)
	assert.NoError(t, err)

	c := &Citation{}
	c.UnmarshalOscal(oscalCit)
	output := c.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestBackMatterResource_OscalMarshalling(t *testing.T) {
	oscalRes := oscaltypes113.Resource{
		UUID:        uuid.New().String(),
		Title:       "title",
		Description: "desc",
		Remarks:     "remarks",
		Citation: &oscaltypes113.Citation{
			Text: "Some Citation",
		},
	}
	inputJson, err := json.Marshal(oscalRes)
	assert.NoError(t, err)

	br := &BackMatterResource{}
	br.UnmarshalOscal(oscalRes)
	output := br.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}

func TestBackMatter_OscalMarshalling(t *testing.T) {
	oscalBM := oscaltypes113.BackMatter{
		Resources: &[]oscaltypes113.Resource{
			{
				UUID:        uuid.New().String(),
				Title:       "res-title",
				Description: "res-desc",
				Remarks:     "res-remarks",
			},
		},
	}
	inputJson, err := json.Marshal(oscalBM)
	assert.NoError(t, err)

	bm := &BackMatter{}
	bm.UnmarshalOscal(oscalBM)
	output := bm.MarshalOscal()
	outputJson, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.JSONEq(t, string(inputJson), string(outputJson))
}
