package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validReport() agentconfig.Report {
	return agentconfig.Report{
		Mode:            agentconfig.ModeApplySafe,
		Daemon:          true,
		Status:          agentconfig.StatusApplied,
		Base:            json.RawMessage(`{}`),
		Effective:       json.RawMessage(`{"api":{"url":"http://x"}}`),
		EffectiveDigest: testDigest,
	}
}

func int64Ptr(v int64) *int64 { return &v }

func TestNormalizeReport_Valid(t *testing.T) {
	for _, mode := range agentconfig.Modes {
		for _, status := range agentconfig.AgentStatuses {
			r := validReport()
			r.Mode = mode
			r.Status = status
			assert.NoError(t, normalizeReport(&r), "mode=%s status=%s", mode, status)
		}
	}
	for _, reason := range agentconfig.Reasons {
		r := validReport()
		r.Status = agentconfig.StatusRejected
		r.Reason = reason
		assert.NoError(t, normalizeReport(&r), "reason=%s", reason)
	}
	r := validReport()
	r.AppliedRevision = int64Ptr(0)
	r.AttemptedRevision = int64Ptr(3)
	r.Base = json.RawMessage("  \n{\"a\":1}")
	assert.NoError(t, normalizeReport(&r))
}

func TestNormalizeReport_Rejects(t *testing.T) {
	cases := map[string]func(r *agentconfig.Report){
		"empty mode":                  func(r *agentconfig.Report) { r.Mode = "" },
		"bad mode":                    func(r *agentconfig.Report) { r.Mode = "apply" },
		"status pending":              func(r *agentconfig.Report) { r.Status = agentconfig.StatusPending },
		"status unknown":              func(r *agentconfig.Report) { r.Status = agentconfig.StatusUnknown },
		"empty status":                func(r *agentconfig.Report) { r.Status = "" },
		"unknown reason":              func(r *agentconfig.Report) { r.Reason = "because" },
		"negative applied-revision":   func(r *agentconfig.Report) { r.AppliedRevision = int64Ptr(-1) },
		"negative attempted-revision": func(r *agentconfig.Report) { r.AttemptedRevision = int64Ptr(-2) },
		"base missing":                func(r *agentconfig.Report) { r.Base = nil },
		"base array":                  func(r *agentconfig.Report) { r.Base = json.RawMessage(`[1]`) },
		"base null":                   func(r *agentconfig.Report) { r.Base = json.RawMessage(`null`) },
		"base string":                 func(r *agentconfig.Report) { r.Base = json.RawMessage(`"x"`) },
		"effective array":             func(r *agentconfig.Report) { r.Effective = json.RawMessage(`[]`) },
		"digest empty":                func(r *agentconfig.Report) { r.EffectiveDigest = "" },
		"digest no prefix":            func(r *agentconfig.Report) { r.EffectiveDigest = strings.TrimPrefix(testDigest, "sha256:") },
		"digest uppercase":            func(r *agentconfig.Report) { r.EffectiveDigest = strings.ToUpper(testDigest) },
		"digest short":                func(r *agentconfig.Report) { r.EffectiveDigest = testDigest[:len(testDigest)-1] },
		"digest long":                 func(r *agentconfig.Report) { r.EffectiveDigest = testDigest + "0" },
		"digest non-hex":              func(r *agentconfig.Report) { r.EffectiveDigest = testDigest[:len(testDigest)-1] + "g" },
		"plugin without a name": func(r *agentconfig.Report) {
			r.Plugins = []agentconfig.PluginReport{{Name: "ssh"}, {Name: "  ", LibVersion: "v0.7.1"}}
		},
		// NUL: Postgres stores it neither in text nor (as \u0000) in jsonb.
		"NUL in hostname":         func(r *agentconfig.Report) { r.Hostname = "h\x00st" },
		"NUL in agent-version":    func(r *agentconfig.Report) { r.AgentVersion = "v1\x00" },
		"NUL in error":            func(r *agentconfig.Report) { e := "boom\x00"; r.Error = &e },
		"NUL in effective-digest": func(r *agentconfig.Report) { r.EffectiveDigest = testDigest[:10] + "\x00" },
		"NUL in warning message": func(r *agentconfig.Report) {
			r.Warnings = []agentconfig.FieldError{{Path: "/x", Code: "c", Message: "m\x00"}}
		},
		"NUL in plugin source": func(r *agentconfig.Report) {
			r.Plugins = []agentconfig.PluginReport{{Name: "ssh", Source: "s\x00"}}
		},
		"NUL in plugin name": func(r *agentconfig.Report) { r.Plugins = []agentconfig.PluginReport{{Name: "s\x00sh"}} },
		"NUL in unsafe value": func(r *agentconfig.Report) {
			r.Unsafe = []agentconfig.Change{{Path: "/p", Safety: agentconfig.Unsafe, Reason: "r", Value: "\x00"}}
		},
		"NUL in remote-config": func(r *agentconfig.Report) {
			r.RemoteConfig = &agentconfig.RemoteConfig{Mode: agentconfig.ModeReport, TrustedSources: []string{"a\x00"}}
		},
		"NUL escape in base":          func(r *agentconfig.Report) { r.Base = json.RawMessage(`{"a":"x\u0000"}`) },
		"NUL escape in effective key": func(r *agentconfig.Report) { r.Effective = json.RawMessage(`{"\u0000":1}`) },
		"NUL escape after an escaped backslash": func(r *agentconfig.Report) {
			r.Base = json.RawMessage(`{"a":"\\\u0000"}`)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReport()
			mutate(&r)
			assert.Error(t, normalizeReport(&r))
		})
	}
}

func TestNormalizeReport_Truncates(t *testing.T) {
	r := validReport()
	r.Warnings = make([]agentconfig.FieldError, maxReportWarnings+1)
	r.Hostname = "  " + strings.Repeat("h", 300) + "  "
	r.AgentVersion = strings.Repeat("v", 100)
	longErr := strings.Repeat("é", maxReportErrorBytes) // 2 bytes each
	r.Error = &longErr
	require.NoError(t, normalizeReport(&r))

	assert.Len(t, r.Warnings, maxReportWarnings)
	assert.True(t, r.Truncated)
	assert.Len(t, r.Hostname, maxReportHostnameLen)
	assert.Len(t, r.AgentVersion, maxReportAgentVersionLen)
	require.NotNil(t, r.Error)
	assert.LessOrEqual(t, len(*r.Error), maxReportErrorBytes)
	assert.True(t, utf8.ValidString(*r.Error))

	// Exactly at the caps: untouched, truncated not forced.
	r = validReport()
	r.Warnings = make([]agentconfig.FieldError, maxReportWarnings)
	r.Hostname = " host "
	msg := "short"
	r.Error = &msg
	require.NoError(t, normalizeReport(&r))
	assert.Len(t, r.Warnings, maxReportWarnings)
	assert.False(t, r.Truncated)
	assert.Equal(t, "host", r.Hostname)
	assert.Equal(t, "short", *r.Error)

	// An agent-set truncated flag is kept.
	r = validReport()
	r.Truncated = true
	require.NoError(t, normalizeReport(&r))
	assert.True(t, r.Truncated)
}

func TestNormalizeReport_LiteralBackslashU0000IsNotNUL(t *testing.T) {
	r := validReport()
	r.Base = json.RawMessage(`{"a":"\\u0000"}`) // the 6 characters \u0000, not a NUL
	assert.NoError(t, normalizeReport(&r))
}

func TestNormalizeReport_CapsSummaryFields(t *testing.T) {
	r := validReport()
	r.Warnings = []agentconfig.FieldError{{
		Path:    strings.Repeat("p", maxReportWarningPathBytes+1),
		Code:    "c",
		Message: strings.Repeat("é", maxReportWarningMessageBytes), // 2 bytes each
	}}
	r.Unsafe = make([]agentconfig.Change, maxReportUnsafe+1)
	r.Unsafe[0] = agentconfig.Change{
		Path:   strings.Repeat("p", maxReportChangePathBytes+1),
		Safety: agentconfig.Unsafe,
		Value:  strings.Repeat("v", maxReportChangeValueBytes+1),
	}
	require.NoError(t, normalizeReport(&r))
	assert.True(t, r.Truncated)
	assert.Len(t, r.Warnings[0].Path, maxReportWarningPathBytes)
	assert.LessOrEqual(t, len(r.Warnings[0].Message), maxReportWarningMessageBytes)
	assert.True(t, utf8.ValidString(r.Warnings[0].Message))
	assert.Len(t, r.Unsafe, maxReportUnsafe)
	assert.Len(t, r.Unsafe[0].Path, maxReportChangePathBytes)
	assert.Len(t, r.Unsafe[0].Value, maxReportChangeValueBytes)

	// At the caps: untouched.
	r = validReport()
	r.Warnings = []agentconfig.FieldError{{Path: "/x", Code: "c", Message: strings.Repeat("m", maxReportWarningMessageBytes)}}
	r.Unsafe = make([]agentconfig.Change, maxReportUnsafe)
	require.NoError(t, normalizeReport(&r))
	assert.False(t, r.Truncated)
	assert.Len(t, r.Unsafe, maxReportUnsafe)
}

func TestScrubReportText(t *testing.T) {
	pgURL := "postgres://app:hunter2@db:5432/app"
	r := validReport()
	errMsg := "dial " + pgURL + ": connection refused"
	r.Error = &errMsg
	r.Warnings = []agentconfig.FieldError{
		{Path: "/plugins/a/config/x", Code: "c", Message: "cannot reach " + pgURL},
		{Path: "/plugins/b/schedule", Code: "c", Message: "bad cron"},
	}
	r.Plugins = []agentconfig.PluginReport{
		{Name: "a", Source: "https://ci:hunter2@plugins.example.com/a.tar.gz"},
		{Name: "b", Source: "ghcr.io/compliance-framework/plugin-b:v1"},
	}
	r.RemoteConfig = &agentconfig.RemoteConfig{
		Mode:           agentconfig.ModeApplySafe,
		TrustedSources: []string{"https://u:p@registry.example.com/*", "ghcr.io/compliance-framework/*"},
	}
	r.Unsafe = []agentconfig.Change{
		{Path: "/plugins/a/source", Safety: agentconfig.Unsafe, Reason: agentconfig.ChangeReasonUntrustedSource, Value: "oci://u:hunter2@reg/x"},
		{Path: "/plugins/b/source", Safety: agentconfig.Unsafe, Reason: agentconfig.ChangeReasonUntrustedSource, Value: "ghcr.io/evil/plugin:v1"},
	}

	assert.True(t, scrubReportText(&r))
	assert.Equal(t, agentconfig.MaskedValue, r.Unsafe[0].Value)
	assert.Equal(t, "ghcr.io/evil/plugin:v1", r.Unsafe[1].Value)
	assert.Equal(t, agentconfig.MaskedValue, *r.Error)
	assert.Equal(t, agentconfig.MaskedValue, r.Warnings[0].Message)
	assert.Equal(t, "bad cron", r.Warnings[1].Message)
	assert.Equal(t, agentconfig.MaskedValue, r.Plugins[0].Source)
	assert.Equal(t, "ghcr.io/compliance-framework/plugin-b:v1", r.Plugins[1].Source)
	assert.Equal(t, []string{agentconfig.MaskedValue, "ghcr.io/compliance-framework/*"}, r.RemoteConfig.TrustedSources)
	assert.Equal(t, agentconfig.ModeApplySafe, r.RemoteConfig.Mode)

	clean := validReport()
	assert.False(t, scrubReportText(&clean))
}

func TestNormalizeReport_Plugins(t *testing.T) {
	r := validReport()
	r.Plugins = []agentconfig.PluginReport{
		{Name: "ssh", Source: "ghcr.io/compliance-framework/plugin-local-ssh:v0.2.0", LibVersion: " v0.1.9 "},
		{Name: "local"},
	}
	require.NoError(t, normalizeReport(&r))
	assert.Equal(t, []agentconfig.PluginReport{
		{Name: "ssh", Source: "ghcr.io/compliance-framework/plugin-local-ssh:v0.2.0", LibVersion: "v0.1.9"},
		{Name: "local"},
	}, r.Plugins)
	assert.False(t, r.Truncated)

	// Over the caps: the plugin list and its free text are cut.
	r = validReport()
	r.Plugins = make([]agentconfig.PluginReport, maxReportPlugins+1)
	for i := range r.Plugins {
		r.Plugins[i].Name = "p"
	}
	r.Plugins[0] = agentconfig.PluginReport{
		Name:       strings.Repeat("n", maxReportPluginNameLen+1),
		Source:     strings.Repeat("s", maxReportPluginSourceLen+1),
		LibVersion: strings.Repeat("v", maxReportPluginLibVersionLen+1),
	}
	require.NoError(t, normalizeReport(&r))
	assert.Len(t, r.Plugins, maxReportPlugins)
	assert.Len(t, r.Plugins[0].Name, maxReportPluginNameLen)
	assert.Len(t, r.Plugins[0].Source, maxReportPluginSourceLen)
	assert.Len(t, r.Plugins[0].LibVersion, maxReportPluginLibVersionLen)
	assert.True(t, r.Truncated)
}

func TestTruncateUTF8(t *testing.T) {
	assert.Equal(t, "abc", truncateUTF8("abc", 3))
	assert.Equal(t, "abc", truncateUTF8("abc", 10))
	assert.Equal(t, "ab", truncateUTF8("abc", 2))
	assert.Equal(t, "", truncateUTF8("abc", 0))
	assert.Equal(t, "", truncateUTF8("", 5))

	// "é" is 2 bytes, "€" 3 bytes, "😀" 4 bytes: never split a rune.
	assert.Equal(t, "a", truncateUTF8("aé", 2))
	assert.Equal(t, "aé", truncateUTF8("aé", 3))
	assert.Equal(t, "", truncateUTF8("€", 2))
	assert.Equal(t, "x", truncateUTF8("x😀", 4))
	assert.Equal(t, "x😀", truncateUTF8("x😀y", 5))

	s := strings.Repeat("日本語", 1000)
	for n := 0; n <= 20; n++ {
		out := truncateUTF8(s, n)
		assert.LessOrEqual(t, len(out), n)
		assert.True(t, utf8.ValidString(out), "n=%d", n)
		assert.True(t, strings.HasPrefix(s, out))
		assert.Greater(t, len(out), n-3, "cuts at most one partial rune")
	}
}

func TestIsJSONObject(t *testing.T) {
	assert.True(t, isJSONObject(json.RawMessage(`{}`)))
	assert.True(t, isJSONObject(json.RawMessage(" \t\n{\"a\":1}")))
	assert.False(t, isJSONObject(nil))
	assert.False(t, isJSONObject(json.RawMessage(``)))
	assert.False(t, isJSONObject(json.RawMessage(`   `)))
	assert.False(t, isJSONObject(json.RawMessage(`null`)))
	assert.False(t, isJSONObject(json.RawMessage(`[]`)))
	assert.False(t, isJSONObject(json.RawMessage(`"{}"`)))
	assert.False(t, isJSONObject(json.RawMessage(`1`)))
}

func jsonBodyContext(contentType, body string) echo.Context {
	req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set(echo.HeaderContentType, contentType)
	}
	return echo.New().NewContext(req, httptest.NewRecorder())
}

func TestReadJSONBody(t *testing.T) {
	t.Run("accepts application/json", func(t *testing.T) {
		data, err := readJSONBody(jsonBodyContext(echo.MIMEApplicationJSON, `{"a":1}`), 1024)
		require.Nil(t, err)
		assert.Equal(t, `{"a":1}`, string(data))
	})
	t.Run("accepts charset parameter", func(t *testing.T) {
		data, err := readJSONBody(jsonBodyContext("application/json; charset=utf-8", `{}`), 1024)
		require.Nil(t, err)
		assert.Equal(t, `{}`, string(data))
	})
	t.Run("accepts mixed case media type", func(t *testing.T) {
		_, err := readJSONBody(jsonBodyContext("Application/JSON", `{}`), 1024)
		assert.Nil(t, err)
	})
	t.Run("accepts missing content type", func(t *testing.T) {
		data, err := readJSONBody(jsonBodyContext("", `{"b":2}`), 1024)
		require.Nil(t, err)
		assert.Equal(t, `{"b":2}`, string(data))
	})
	t.Run("415 on text/plain", func(t *testing.T) {
		_, err := readJSONBody(jsonBodyContext("text/plain", `{}`), 1024)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusUnsupportedMediaType, err.status)
	})
	t.Run("415 on malformed content type", func(t *testing.T) {
		_, err := readJSONBody(jsonBodyContext("application/json; =", `{}`), 1024)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusUnsupportedMediaType, err.status)
	})
	t.Run("exactly at the limit", func(t *testing.T) {
		data, err := readJSONBody(jsonBodyContext(echo.MIMEApplicationJSON, strings.Repeat("a", 16)), 16)
		require.Nil(t, err)
		assert.Len(t, data, 16)
	})
	t.Run("413 over the limit", func(t *testing.T) {
		ctx := jsonBodyContext(echo.MIMEApplicationJSON, strings.Repeat("a", 17))
		_, err := readJSONBody(ctx, 16)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusRequestEntityTooLarge, err.status)
		assert.Equal(t, "request body exceeds 16 bytes", err.msg)
		require.NoError(t, err.respond(ctx))
		assert.Equal(t, http.StatusRequestEntityTooLarge, ctx.Response().Status)
	})
	t.Run("413 from a MaxBytesReader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(strings.Repeat("a", 64)))
		rec := httptest.NewRecorder()
		req.Body = http.MaxBytesReader(rec, req.Body, 8)
		_, err := readJSONBody(echo.New().NewContext(req, rec), 32)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusRequestEntityTooLarge, err.status)
	})
	t.Run("400 on a read error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/", iotest.ErrReader(errors.New("boom")))
		_, err := readJSONBody(echo.New().NewContext(req, httptest.NewRecorder()), 32)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.status)
		assert.Equal(t, "failed to read request body", err.msg)
	})
}
