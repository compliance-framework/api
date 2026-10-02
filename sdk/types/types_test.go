package types

import (
	"encoding/json"
	"testing"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
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

func TestSubjectCarriesSubjectUUIDAndTitle(t *testing.T) {
	id := uuid.MustParse("5b1c4b1e-2f0f-4b8e-9a44-0d6a2f7e1c11")
	raw, err := json.Marshal(Subject{SubjectUUID: &id, Title: "Perimeter Firewall"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"subject-uuid":"5b1c4b1e-2f0f-4b8e-9a44-0d6a2f7e1c11","title":"Perimeter Firewall"}`, string(raw))

	legacy, err := json.Marshal(Subject{Identifier: "github/acme", Type: "Component"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"identifier":"github/acme","type":"Component"}`, string(legacy),
		"unset subject-uuid and title are omitted")
}

func TestSubjectTemplateCarriesDisplayPriorityAndComponentType(t *testing.T) {
	raw, err := json.Marshal(SubjectTemplate{DisplayPriority: 10, ComponentType: "software"})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"display-priority":10`)
	assert.Contains(t, string(raw), `"component-type":"software"`)

	unset, err := json.Marshal(SubjectTemplate{})
	require.NoError(t, err)
	assert.NotContains(t, string(unset), "display-priority", "the API default (0) applies when unset")
	assert.NotContains(t, string(unset), "component-type", "the API default (service) applies when unset")
}
