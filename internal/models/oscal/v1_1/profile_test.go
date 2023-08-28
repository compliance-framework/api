package v1_1

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfile(t *testing.T) {
	a, err := os.ReadFile("testdata/profile.json")
	require.Nil(t, err)
	expect := make(map[string]interface{})
	err = json.Unmarshal(a, &expect)
	require.Nil(t, err)
	c := Profile{}
	err = c.FromJSON(a)
	require.Nil(t, err)
	b, err := c.ToJSON()
	require.Nil(t, err)
	got := make(map[string]interface{})
	err = json.Unmarshal(b, &got)
	require.Nil(t, err)
	assert.Equal(t, expect, got)
}
