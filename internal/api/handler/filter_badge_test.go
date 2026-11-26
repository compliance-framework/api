package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

// resolveBody decodes body as a filter request and applies its badge to current.
func resolveBody(t *testing.T, current relational.FilterBadge, body string) (relational.FilterBadge, error) {
	t.Helper()
	var req createFilterRequest
	require.NoError(t, json.Unmarshal([]byte(body), &req))
	return resolveFilterBadge(current, req.Badge, req.badgeSet)
}

func TestResolveFilterBadge(t *testing.T) {
	published := relational.FilterBadge{Enabled: true, Label: "payments", Slug: strPtr("payments")}
	unpublished := relational.FilterBadge{Label: "payments", Slug: strPtr("payments")}

	cases := []struct {
		name    string
		current relational.FilterBadge
		body    string
		want    relational.FilterBadge
		wantErr bool
	}{
		{"omitted keeps settings", published, `{}`, published, false},
		{"null resets to defaults", published, `{"badge":null}`, relational.DefaultFilterBadge(), false},
		{"empty object keeps settings", published, `{"badge":{}}`, published, false},
		{"disable keeps slug", published, `{"badge":{"enabled":false}}`, unpublished, false},
		{"slug null clears and unpublishes, keeps label", published, `{"badge":{"slug":null}}`, relational.FilterBadge{Label: "payments"}, false},
		{"enable with slug", relational.DefaultFilterBadge(), `{"badge":{"enabled":true,"slug":"a-1"}}`, relational.FilterBadge{Enabled: true, Label: "compliance", Slug: strPtr("a-1")}, false},
		{"label trimmed", relational.DefaultFilterBadge(), `{"badge":{"label":"  ok  "}}`, relational.FilterBadge{Label: "ok"}, false},
		{"enable without slug", relational.DefaultFilterBadge(), `{"badge":{"enabled":true}}`, relational.FilterBadge{}, true},
		{"enable with null slug", published, `{"badge":{"enabled":true,"slug":null}}`, relational.FilterBadge{}, true},
		{"empty slug", relational.DefaultFilterBadge(), `{"badge":{"slug":""}}`, relational.FilterBadge{}, true},
		{"uppercase slug not lowercased", relational.DefaultFilterBadge(), `{"badge":{"slug":"Payments"}}`, relational.FilterBadge{}, true},
		{"double hyphen", relational.DefaultFilterBadge(), `{"badge":{"slug":"a--b"}}`, relational.FilterBadge{}, true},
		{"leading hyphen", relational.DefaultFilterBadge(), `{"badge":{"slug":"-a"}}`, relational.FilterBadge{}, true},
		{"slug with suffix", relational.DefaultFilterBadge(), `{"badge":{"slug":"a.svg"}}`, relational.FilterBadge{}, true},
		{"slug too long", relational.DefaultFilterBadge(), `{"badge":{"slug":"` + strings.Repeat("a", 64) + `"}}`, relational.FilterBadge{}, true},
		{"blank label", relational.DefaultFilterBadge(), `{"badge":{"label":"   "}}`, relational.FilterBadge{}, true},
		{"label too long", relational.DefaultFilterBadge(), `{"badge":{"label":"` + strings.Repeat("é", 65) + `"}}`, relational.FilterBadge{}, true},
		{"label control char", relational.DefaultFilterBadge(), `{"badge":{"label":"a\u0007b"}}`, relational.FilterBadge{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBody(t, tc.current, tc.body)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, badgeEqual(tc.want, got), "got %+v (slug %v), want %+v", got, got.Slug, tc.want)
		})
	}

	// The longest valid slug is accepted.
	_, err := resolveBody(t, relational.DefaultFilterBadge(), `{"badge":{"slug":"`+strings.Repeat("a", 63)+`"}}`)
	assert.NoError(t, err)
}

func TestFilterBadgeRequestRejectsMalformed(t *testing.T) {
	for _, body := range []string{
		`{"badge":[]}`,
		`{"badge":"x"}`,
		`{"badge":{"enabled":null}}`,
		`{"badge":{"enabled":"yes"}}`,
		`{"badge":{"label":null}}`,
		`{"badge":{"slug":1}}`,
	} {
		var req createFilterRequest
		assert.Errorf(t, json.Unmarshal([]byte(body), &req), "body %s", body)
	}
}
