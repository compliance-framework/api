package v1_1

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAP(t *testing.T) {
	a, err := os.ReadFile("testdata/assessment-plan.json")
	require.Nil(t, err)
	expect := make(map[string]interface{})
	err = json.Unmarshal(a, &expect)
	require.Nil(t, err)
	c := AssessmentPlan{}
	err = c.FromJSON(a)
	require.Nil(t, err)
	b, err := c.ToJSON()
	require.Nil(t, err)
	got := make(map[string]interface{})
	err = json.Unmarshal(b, &got)
	require.Nil(t, err)
	assert.Equal(t, expect, got)
}

func TestAPValidate(t *testing.T) {
	a, err := os.ReadFile("testdata/assessment-plan.json")
	require.Nil(t, err)
	c := AssessmentPlan{}
	err = c.FromJSON(a)
	require.Nil(t, err)
	err = c.Validate()
	assert.Nil(t, err)
}
