package types

import (
	"encoding/json"
	"testing"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceRoundTripsBackMatter(t *testing.T) {
	in := Evidence{
		Title: "with back-matter",
		BackMatter: &oscalTypes_1_1_3.BackMatter{
			Resources: &[]oscalTypes_1_1_3.Resource{
				{UUID: "7f5b4b1e-2f0f-4b8e-9a44-0d6a2f7e1c11", Title: "Raw scan output"},
			},
		},
	}

	raw, err := json.Marshal(in)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"back-matter"`)

	var out Evidence
	require.NoError(t, json.Unmarshal(raw, &out))
	require.NotNil(t, out.BackMatter)
	require.NotNil(t, out.BackMatter.Resources)
	require.Len(t, *out.BackMatter.Resources, 1)
	assert.Equal(t, "Raw scan output", (*out.BackMatter.Resources)[0].Title)
}

func TestEvidenceOmitsEmptyBackMatter(t *testing.T) {
	raw, err := json.Marshal(Evidence{Title: "plain"})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"back-matter"`)
}
