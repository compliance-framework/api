package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestParseComplianceBadgeParams(t *testing.T) {
	tests := []struct {
		name      string
		params    url.Values
		maxParams int
		wantErr   bool
	}{
		{name: "one arbitrary label", params: url.Values{"provider": {"aws"}}, maxParams: 3},
		{name: "three labels at limit", params: url.Values{"source": {"github"}, "repo": {"any-format"}, "branch": {"release/2026"}}, maxParams: 3},
		{name: "internal spaces", params: url.Values{"team": {"platform team"}}, maxParams: 3},
		{name: "Unicode boundary", params: url.Values{"team": {strings.Repeat("é", complianceBadgeMaxParamLength)}}, maxParams: 3},
		{name: "custom larger limit", params: url.Values{"a": {"1"}, "b": {"2"}, "c": {"3"}, "d": {"4"}}, maxParams: 4},
		{name: "no labels", maxParams: 3, wantErr: true},
		{name: "over default limit", params: url.Values{"a": {"1"}, "b": {"2"}, "c": {"3"}, "d": {"4"}}, maxParams: 3, wantErr: true},
		{name: "over custom limit", params: url.Values{"a": {"1"}, "b": {"2"}}, maxParams: 1, wantErr: true},
		{name: "repeated key", params: url.Values{"team": {"a", "b"}}, maxParams: 3, wantErr: true},
		{name: "case-insensitive repeated key", params: url.Values{"team": {"a"}, "Team": {"b"}}, maxParams: 3, wantErr: true},
		{name: "empty name", params: url.Values{"": {"a"}}, maxParams: 3, wantErr: true},
		{name: "empty value", params: url.Values{"team": {""}}, maxParams: 3, wantErr: true},
		{name: "missing value", params: url.Values{"team": nil}, maxParams: 3, wantErr: true},
		{name: "surrounding whitespace", params: url.Values{"team": {" a "}}, maxParams: 3, wantErr: true},
		{name: "name whitespace", params: url.Values{" team": {"a"}}, maxParams: 3, wantErr: true},
		{name: "control character", params: url.Values{"team": {"a\nb"}}, maxParams: 3, wantErr: true},
		{name: "name control character", params: url.Values{"te\x00am": {"a"}}, maxParams: 3, wantErr: true},
		{name: "oversized value", params: url.Values{"team": {strings.Repeat("a", complianceBadgeMaxParamLength+1)}}, maxParams: 3, wantErr: true},
		{name: "oversized name", params: url.Values{strings.Repeat("a", complianceBadgeMaxParamLength+1): {"a"}}, maxParams: 3, wantErr: true},
		{name: "invalid UTF-8", params: url.Values{"team": {"\xff"}}, maxParams: 3, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := parseComplianceBadgeParams(tt.params, tt.maxParams)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, filter.Scope.Query)
			assert.Equal(t, "and", filter.Scope.Query.Operator)
			require.Len(t, filter.Scope.Scopes, len(tt.params))
			for _, scope := range filter.Scope.Scopes {
				require.NotNil(t, scope.Condition)
				assert.Equal(t, "=", scope.Condition.Operator)
				assert.Equal(t, tt.params.Get(scope.Label), scope.Value)
			}
		})
	}
}

func TestComplianceBadgeFilter(t *testing.T) {
	filter, err := parseComplianceBadgeParams(url.Values{"provider": {"aws"}, "environment": {"production"}, "team": {"platform team"}}, 3)
	require.NoError(t, err)

	require.NotNil(t, filter.Scope)
	require.NotNil(t, filter.Scope.Query)
	assert.Equal(t, "and", filter.Scope.Query.Operator)
	require.Len(t, filter.Scope.Scopes, 3)
	assert.Equal(t, &labelfilter.Condition{Label: "environment", Operator: "=", Value: "production"}, filter.Scope.Query.Scopes[0].Condition)
	assert.Equal(t, &labelfilter.Condition{Label: "provider", Operator: "=", Value: "aws"}, filter.Scope.Query.Scopes[1].Condition)
	assert.Equal(t, &labelfilter.Condition{Label: "team", Operator: "=", Value: "platform team"}, filter.Scope.Query.Scopes[2].Condition)
}

func TestComplianceBadgeInvalidQueries(t *testing.T) {
	h := NewEvidenceHandler(zap.NewNop().Sugar(), nil, nil)
	require.Equal(t, 3, h.badgeMaxParams)
	server := echo.New()
	server.GET("/badge.svg", h.ComplianceBadge)
	for _, query := range []string{"", "team=a&team=b", "a=1&b=2&c=3&d=4", "team=", "team=%ZZ", "team=a;ignored=b"} {
		t.Run(query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/badge.svg?"+query, nil))
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), `"errors"`)
		})
	}
}

func TestComplianceBadgeReturns429WhenBusy(t *testing.T) {
	h := NewEvidenceHandler(zap.NewNop().Sugar(), nil, nil)
	for range cap(h.badgeSlots) {
		h.badgeSlots <- struct{}{}
	}

	req := httptest.NewRequest(http.MethodGet, "/badge.svg?team=platform", nil)
	rec := httptest.NewRecorder()
	err := h.ComplianceBadge(echo.New().NewContext(req, rec))

	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "too many compliance badge requests")
}

func TestComplianceBadgeSVG(t *testing.T) {
	tests := []struct {
		status string
		color  string
	}{
		{status: relational.EvidenceStatusSatisfied, color: "#4c1"},
		{status: relational.EvidenceStatusNotSatisfied, color: "#e05d44"},
		{status: "unknown", color: "#9f9f9f"},
		{status: "unrecognized", color: "#9f9f9f"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			svg := complianceBadgeSVG(tt.status)
			assert.Contains(t, svg, `xmlns="http://www.w3.org/2000/svg"`)
			assert.Contains(t, svg, `fill="`+tt.color+`"`)
			assert.Contains(t, svg, "Compliance status:")
			assert.Contains(t, svg, `>compliance</text>`)
		})
	}

	assert.Contains(t, complianceBadgeSVG("unknown"), `aria-label="Compliance status: unknown"`)
	assert.NotContains(t, complianceBadgeSVG("unrecognized"), "unrecognized", "unknown input must not be reflected into SVG markup")
}

func TestComplianceBadgeStatus(t *testing.T) {
	tests := []struct {
		name string
		rows []evidencesvc.StatusCount
		want string
	}{
		{name: "not satisfied takes precedence", rows: []evidencesvc.StatusCount{
			{Count: 1, Status: relational.EvidenceStatusSatisfied},
			{Count: 1, Status: relational.EvidenceStatusNotSatisfied},
		}, want: relational.EvidenceStatusNotSatisfied},
		{name: "satisfied when no failures", rows: []evidencesvc.StatusCount{
			{Count: 1, Status: relational.EvidenceStatusSatisfied},
			{Count: 1, Status: "unknown"},
		}, want: relational.EvidenceStatusSatisfied},
		{name: "unknown when no known positive counts", rows: []evidencesvc.StatusCount{
			{Count: 0, Status: relational.EvidenceStatusNotSatisfied},
		}, want: "unknown"},
		{name: "unknown when there are no counts", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, complianceBadgeStatus(tt.rows))
		})
	}
}
