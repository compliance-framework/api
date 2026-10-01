package policyeval

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateModules(t *testing.T) {
	t.Run("a bundle file may be called policy.rego", func(t *testing.T) {
		resp, err := EvaluateModules(context.Background(), EvaluateModulesRequest{
			Modules: map[string]string{
				PolicyModuleName: `package compliance_framework.ports

import data.ccf_libs.helpers

title := "Only approved ports are open"

violation contains {"id": "unapproved-port"} if {
	some port in input.open_ports
	not helpers.approved(port)
}
`,
				"lib/helpers.rego": `package ccf_libs.helpers

approved(port) if port in data.config.approved_ports
`,
			},
			Input: map[string]any{"open_ports": []any{22, 8080}},
			Data:  map[string]any{"config": map[string]any{"approved_ports": []any{22}}},
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		assert.Equal(t, "compliance_framework.ports", resp.Results[0].Package)
		assert.Equal(t, PolicyModuleName, resp.Results[0].File)
		assert.Equal(t, StatusNotSatisfied, resp.Results[0].Status)
	})

	t.Run("runs in the sandbox", func(t *testing.T) {
		_, err := EvaluateModules(context.Background(), EvaluateModulesRequest{
			Modules: map[string]string{"p.rego": "package compliance_framework.p\n\ntitle := \"p\"\n\nleak := http.send({\"method\": \"GET\", \"url\": \"http://example.com\"})\n"},
			Input:   map[string]any{},
		})
		evalErrs := requireEvalErrors(t, err)
		assert.Equal(t, "rego_type_error", evalErrs.Errors[0].Code)
	})

	t.Run("rejects an empty module name", func(t *testing.T) {
		_, err := EvaluateModules(context.Background(), EvaluateModulesRequest{Modules: map[string]string{"": "package x"}})
		assert.Equal(t, ErrCodeModuleName, requireEvalErrors(t, err).Errors[0].Code)
	})
}

func TestMergeData(t *testing.T) {
	base := map[string]any{
		"config":  map[string]any{"approved_ports": []any{22, 443}, "owner": "platform"},
		"release": "2026.09",
	}
	overlay := map[string]any{
		"config": map[string]any{"approved_ports": []any{22}},
		"extra":  true,
	}

	merged := MergeData(base, overlay)

	assert.Equal(t, map[string]any{
		"config":  map[string]any{"approved_ports": []any{22}, "owner": "platform"},
		"release": "2026.09",
		"extra":   true,
	}, merged)
	assert.Equal(t, []any{22, 443}, base["config"].(map[string]any)["approved_ports"], "base is not modified")
	assert.Equal(t, map[string]any{}, MergeData(nil, nil))
}
