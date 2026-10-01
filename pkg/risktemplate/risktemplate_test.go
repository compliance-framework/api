package risktemplate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidHint(t *testing.T) {
	for value, want := range map[string]bool{
		"":                    true,
		"   ":                 true,
		"low":                 true,
		" High ":              true,
		"medium":              true, // legacy, normalized to moderate
		"moderate":            true,
		"critical":            true,
		"negligible":          true,
		"{{ .severity }}":     true,
		"severe":              false,
		"5":                   false,
		"low-ish":             false,
		"{{ .severity":        true, // templated: syntax is checked with the label schema, not here
		"Critical{{ .x }}foo": true,
	} {
		assert.Equal(t, want, ValidHint(value), "%q", value)
	}
}

func TestNormalizeRiskLevel(t *testing.T) {
	assert.Equal(t, "moderate", NormalizeRiskLevel(" Medium "))
	assert.Equal(t, "high", NormalizeRiskLevel("HIGH"))
	assert.Equal(t, "nope", NormalizeRiskLevel("nope"))
}

func TestTemplateLabelKeys(t *testing.T) {
	keys, err := TemplateLabelKeys(`{{ .repo }} in {{ if .org }}{{ .org }}{{ else }}{{ .fallback }}{{ end }} {{ range .items }}{{ end }} {{ with .owner }}x{{ end }} {{ printf "%s" .team }}`)
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"repo": {}, "org": {}, "fallback": {}, "items": {}, "owner": {}, "team": {}}, keys)

	keys, err = TemplateLabelKeys("plain text")
	require.NoError(t, err)
	assert.Empty(t, keys)

	_, err = TemplateLabelKeys("{{ .open ")
	assert.Error(t, err)
}
