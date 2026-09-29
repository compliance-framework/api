package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const playbackTestPolicy = `package compliance_framework.ssh_root_login

title := "Root login is disabled"

violation contains {"id": "root-login-enabled"} if {
	print("PermitRootLogin =", input.PermitRootLogin)
	input.PermitRootLogin == "yes"
}
`

func newTestPlaybackHandler(cfg *config.PlaybackConfig) *PlaybackHandler {
	return NewPlaybackHandler(zap.NewNop().Sugar(), cfg)
}

func postPlayback(t *testing.T, h *PlaybackHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/playback/evaluate", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	require.NoError(t, h.Evaluate(echo.New().NewContext(req, rec)))
	return rec
}

func playbackBody(t *testing.T, req map[string]any) string {
	t.Helper()
	b, err := json.Marshal(req)
	require.NoError(t, err)
	return string(b)
}

func TestPlaybackHandlerEvaluate(t *testing.T) {
	t.Run("200 with interpreted result and prints", func(t *testing.T) {
		rec := postPlayback(t, newTestPlaybackHandler(nil), playbackBody(t, map[string]any{
			"policy": playbackTestPolicy,
			"input":  map[string]any{"PermitRootLogin": "yes"},
		}))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var resp policyeval.EvaluateResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Len(t, resp.Results, 1)
		assert.Equal(t, "compliance_framework.ssh_root_login", resp.Results[0].Package)
		assert.Equal(t, policyeval.StatusNotSatisfied, resp.Results[0].Status)
		assert.Len(t, resp.Results[0].Violations, 1)
		assert.Len(t, resp.Prints, 1)
	})

	t.Run("400 on malformed JSON", func(t *testing.T) {
		rec := postPlayback(t, newTestPlaybackHandler(nil), `{"policy":`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("400 when policy is missing", func(t *testing.T) {
		rec := postPlayback(t, newTestPlaybackHandler(nil), `{"input": {}}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "policy is required")
	})

	t.Run("400 when input is missing", func(t *testing.T) {
		rec := postPlayback(t, newTestPlaybackHandler(nil), playbackBody(t, map[string]any{"policy": playbackTestPolicy}))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "input is required")
	})

	t.Run("413 when body is over the limit", func(t *testing.T) {
		cfg := config.DefaultPlaybackConfig()
		cfg.MaxBytes = 64
		rec := postPlayback(t, newTestPlaybackHandler(cfg), playbackBody(t, map[string]any{
			"policy": playbackTestPolicy,
			"input":  map[string]any{},
		}))
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})

	t.Run("422 with location on compile error", func(t *testing.T) {
		rec := postPlayback(t, newTestPlaybackHandler(nil), playbackBody(t, map[string]any{
			"policy": "package compliance_framework.escape\n\ntitle := \"x\"\n\nleak := http.send({\"method\": \"GET\", \"url\": \"http://example.com\"})\n",
			"input":  map[string]any{},
		}))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())

		var resp policyeval.ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.NotEmpty(t, resp.Errors)
		assert.Equal(t, "rego_type_error", resp.Errors[0].Code)
		assert.Equal(t, policyeval.PolicyModuleName, resp.Errors[0].File)
		assert.Equal(t, 5, resp.Errors[0].Row)
	})

	t.Run("422 eval_timeout past the time limit", func(t *testing.T) {
		cfg := config.DefaultPlaybackConfig()
		cfg.Timeout = 50 * time.Millisecond
		items := make([]int, 1000)
		rec := postPlayback(t, newTestPlaybackHandler(cfg), playbackBody(t, map[string]any{
			"policy": `package compliance_framework.slow

title := sprintf("%d", [count([1 | some a in input.items; some b in input.items; some c in input.items])])
`,
			"input": map[string]any{"items": items},
		}))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), policyeval.ErrCodeTimeout)
	})

	t.Run("422 no_policies", func(t *testing.T) {
		rec := postPlayback(t, newTestPlaybackHandler(nil), playbackBody(t, map[string]any{
			"policy": "package elsewhere\n\ntitle := \"x\"\n",
			"input":  map[string]any{},
		}))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		assert.Contains(t, rec.Body.String(), policyeval.ErrCodeNoPolicies)
	})

	t.Run("429 when every slot is busy", func(t *testing.T) {
		cfg := config.DefaultPlaybackConfig()
		cfg.MaxConcurrent = 1
		h := newTestPlaybackHandler(cfg)
		h.slots <- struct{}{}
		defer func() { <-h.slots }()

		rec := postPlayback(t, h, playbackBody(t, map[string]any{
			"policy": playbackTestPolicy,
			"input":  map[string]any{},
		}))
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	})
}
