package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression (review #476/#480, fp 5d771b4b3d43): a stored report's summary fields, which the
// instance list returns for every instance on a page, stay within
// maxReportSummaryEncodedBytes once JSON-encoded with HTML escaping, whatever their content.

// summaryEncodedLen encodes a report's summary fields the way the instance list does
// (encoding/json, HTML escaping on), keys included.
func summaryEncodedLen(t *testing.T, r agentconfig.Report) int {
	t.Helper()
	raw, err := json.Marshal(struct {
		Hostname     string                     `json:"hostname"`
		AgentVersion string                     `json:"agent-version"`
		Error        *string                    `json:"error"`
		Warnings     []agentconfig.FieldError   `json:"warnings"`
		Unsafe       []agentconfig.Change       `json:"unsafe"`
		Plugins      []agentconfig.PluginReport `json:"plugins"`
		RemoteConfig *agentconfig.RemoteConfig  `json:"remote-config,omitempty"`
	}{r.Hostname, r.AgentVersion, r.Error, r.Warnings, r.Unsafe, r.Plugins, r.RemoteConfig})
	require.NoError(t, err)
	return len(raw)
}

// summaryKeysOverhead is what summaryEncodedLen adds to the budgeted fields: the object's
// braces, keys and separators.
const summaryKeysOverhead = 128

// capsReport fills every capped summary field of a report with fill: exactly at each count
// and byte cap when over is 0, over them otherwise (one more entry, 16 more bytes).
func capsReport(fill string, over int) agentconfig.Report {
	text := func(n int) string { return strings.Repeat(fill, (n+over*16)/len(fill)) }
	count := func(n int) int { return n + over }
	r := validReport()
	r.Hostname = text(maxReportHostnameLen)
	r.AgentVersion = text(maxReportAgentVersionLen)
	errText := text(maxReportErrorBytes)
	r.Error = &errText
	for range count(maxReportWarnings) {
		r.Warnings = append(r.Warnings, agentconfig.FieldError{
			Path: text(maxReportWarningPathBytes), Code: text(maxReportWarningCodeBytes), Message: text(maxReportWarningMessageBytes),
		})
	}
	for range count(maxReportUnsafe) {
		r.Unsafe = append(r.Unsafe, agentconfig.Change{
			Path: text(maxReportChangePathBytes), Safety: agentconfig.Safety(text(maxReportChangeSafetyBytes)),
			Reason: text(maxReportChangeReasonBytes), Value: text(maxReportChangeValueBytes),
		})
	}
	for range count(maxReportPlugins) {
		r.Plugins = append(r.Plugins, agentconfig.PluginReport{
			Name: text(maxReportPluginNameLen), Source: text(maxReportPluginSourceLen), LibVersion: text(maxReportPluginLibVersionLen),
		})
	}
	// Remote-config entries are capped on their encoded size already; fill them to that cap.
	entry, _ := json.Marshal(strings.Repeat(fill, 1))
	perFill := len(entry) - 2
	rc := &agentconfig.RemoteConfig{
		Mode:         text(maxReportRemoteModeLen),
		PollInterval: text(maxReportRemotePollIntervalLen),
	}
	for range count(maxReportRemoteListEntries) {
		e := strings.Repeat(fill, (maxReportRemoteEntryBytes-2)/perFill)
		rc.TrustedSources = append(rc.TrustedSources, e)
		rc.OverridableConfigFlags = append(rc.OverridableConfigFlags, e)
	}
	r.RemoteConfig = rc
	return r
}

// The fields that had no length cap (warnings[].code, unsafe[].safety, unsafe[].reason) are
// cut, not rejected: a newer agent may send codes or reasons this API does not know.
func TestNormalizeReportCapsCodeSafetyAndReason(t *testing.T) {
	r := validReport()
	r.Warnings = []agentconfig.FieldError{
		{Path: "/a", Code: strings.Repeat("<", 3_500_000), Message: "m"},
		{Path: "/b", Code: "a-code-from-a-newer-agent", Message: "m"},
	}
	r.Unsafe = []agentconfig.Change{
		{Path: "/c", Safety: agentconfig.Safety(strings.Repeat("s", 1000)), Reason: strings.Repeat("r", 1000)},
		{Path: "/d", Safety: "a-newer-safety", Reason: "a-newer-reason"},
	}
	require.NoError(t, normalizeReportErr(&r))
	assert.True(t, r.Truncated)
	assert.Equal(t, strings.Repeat("<", maxReportWarningCodeBytes), r.Warnings[0].Code)
	assert.Equal(t, "a-code-from-a-newer-agent", r.Warnings[1].Code, "unknown codes are kept")
	assert.Len(t, string(r.Unsafe[0].Safety), maxReportChangeSafetyBytes)
	assert.Len(t, r.Unsafe[0].Reason, maxReportChangeReasonBytes)
	assert.Equal(t, agentconfig.Safety("a-newer-safety"), r.Unsafe[1].Safety)
	assert.Equal(t, "a-newer-reason", r.Unsafe[1].Reason)
	assert.Len(t, r.Warnings, 2)
	assert.Less(t, summaryEncodedLen(t, r), 4<<10)
}

// Content that JSON escapes (each '<', '&' or control character encodes to six bytes) is cut
// to the budget: trailing list entries are dropped and the error text is cut.
func TestNormalizeReportSummaryBudgetAfterEscaping(t *testing.T) {
	for _, fill := range []string{"<", "&", "\x01", "<&\x1f"} {
		for _, over := range []int{0, 1} {
			r := capsReport(fill, over)
			raw := capsReport(fill, over)
			require.NoError(t, normalizeReportErr(&r))
			assert.True(t, r.Truncated, "%q over=%d", fill, over)
			size := summaryEncodedLen(t, r)
			assert.LessOrEqual(t, size, maxReportSummaryEncodedBytes+summaryKeysOverhead, "%q over=%d", fill, over)
			assert.Greater(t, size, maxReportSummaryEncodedBytes*9/10, "%q over=%d: only what is needed is dropped", fill, over)

			errLen, err := encodedLen(*r.Error)
			require.NoError(t, err)
			assert.LessOrEqual(t, errLen, maxReportErrorEncodedBytes)
			assert.True(t, strings.HasPrefix(*raw.Error, *r.Error), "the error text is cut, not replaced")
			assert.NotEmpty(t, r.Warnings)
			assert.NotEmpty(t, r.Unsafe)
			assert.NotEmpty(t, r.Plugins)
			// The entries kept are the first ones, as the byte caps left them.
			assert.Equal(t, truncateUTF8(raw.Warnings[0].Message, maxReportWarningMessageBytes), r.Warnings[0].Message)
			assert.Equal(t, truncateUTF8(raw.Plugins[0].Source, maxReportPluginSourceLen), r.Plugins[0].Source)
		}
	}
}

// A plain-text report at every cap fits the budget, so the budget leaves it unchanged.
func TestNormalizeReportPlainTextAtCapsIsUnchanged(t *testing.T) {
	r := capsReport("x", 0)
	want := capsReport("x", 0)
	require.NoError(t, normalizeReportErr(&r))
	assert.False(t, r.Truncated)
	assert.Equal(t, want, r)
	assert.LessOrEqual(t, summaryEncodedLen(t, r), maxReportSummaryEncodedBytes)
}

// A typical report is stored as sent.
func TestNormalizeReportTypicalReportIsUnchanged(t *testing.T) {
	build := func() agentconfig.Report {
		r := validReport()
		errText := `plugin "ssh": dial tcp 10.0.0.1:22: i/o timeout` + "\n" + `<retrying & giving up>`
		r.Error = &errText
		r.Hostname = "host-1.example.com"
		r.AgentVersion = "v1.4.0"
		r.Warnings = []agentconfig.FieldError{{Path: "/plugins/ssh/foo", Code: agentconfig.FieldCodeUnknownField, Message: `unknown field "foo"`}}
		r.Unsafe = []agentconfig.Change{{Path: "/plugins/ssh/source", Safety: agentconfig.Unsafe, Reason: agentconfig.ChangeReasonUntrustedSource, Value: "ghcr.io/x/ssh:v2"}}
		r.Plugins = []agentconfig.PluginReport{{Name: "ssh", Source: "ghcr.io/x/ssh:v1", LibVersion: "v0.7.1"}}
		r.RemoteConfig = &agentconfig.RemoteConfig{Mode: agentconfig.ModeApplySafe, PollInterval: "60s", TrustedSources: []string{"ghcr.io/x/*"}, OverridableConfigFlags: []string{}}
		return r
	}
	r := build()
	require.NoError(t, normalizeReportErr(&r))
	assert.False(t, r.Truncated)
	assert.Equal(t, build(), r)
}
