package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAnthropicClientErrorMapping(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		expected error
	}{
		{
			name:     "auth",
			status:   http.StatusUnauthorized,
			body:     `{"type":"error","error":{"type":"authentication_error","message":"bad key"}}`,
			expected: ErrAuth,
		},
		{
			name:     "invalid output",
			status:   http.StatusBadRequest,
			body:     `{"type":"error","error":{"type":"invalid_request_error","message":"bad schema"}}`,
			expected: ErrInvalidOutput,
		},
		{
			name:     "rate limited",
			status:   http.StatusTooManyRequests,
			body:     `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`,
			expected: ErrRateLimited,
		},
		{
			name:     "overloaded",
			status:   529,
			body:     `{"type":"error","error":{"type":"overloaded_error","message":"try later"}}`,
			expected: ErrOverloaded,
		},
		{
			name:     "malformed body",
			status:   http.StatusOK,
			body:     `{`,
			expected: ErrInvalidOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1/messages", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)

			client := NewAnthropicClient(AnthropicConfig{
				Enabled:        true,
				APIKey:         "test-key",
				Model:          "claude-test",
				BaseURL:        server.URL,
				RequestTimeout: time.Second,
			})

			_, err := client.CompleteStructured(context.Background(), StructuredRequest{
				Prompt:    "prompt",
				Schema:    map[string]any{"type": "object"},
				MaxTokens: 64,
			})

			require.Error(t, err)
			require.Truef(t, errors.Is(err, tt.expected), "expected %v, got %v", tt.expected, err)
		})
	}
}

func TestAnthropicClientStructuredOutputSchemaPassthrough(t *testing.T) {
	rawOutput := `{"answer":"ok","items":[1,2]}`
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"answer": map[string]any{"type": "string", "minLength": float64(2)},
			"items": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "integer", "minimum": float64(1)},
			},
		},
		"required": []any{"answer", "items"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/messages", r.URL.Path)

		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))

		require.Equal(t, "claude-test", payload["model"])
		require.Equal(t, float64(321), payload["max_tokens"])

		system, ok := payload["system"].([]any)
		require.True(t, ok)
		require.Len(t, system, 1)
		require.Equal(t, "system prompt", system[0].(map[string]any)["text"])

		messages, ok := payload["messages"].([]any)
		require.True(t, ok)
		require.Len(t, messages, 1)
		require.Equal(t, "user", messages[0].(map[string]any)["role"])

		outputConfig := payload["output_config"].(map[string]any)
		format := outputConfig["format"].(map[string]any)
		require.Equal(t, "json_schema", format["type"])
		require.Equal(t, schema, format["schema"])

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"msg_test",
			"type":"message",
			"role":"assistant",
			"model":"claude-test",
			"content":[{"type":"text","text":` + strconvQuote(rawOutput) + `}],
			"stop_reason":"end_turn",
			"stop_sequence":"",
			"usage":{"input_tokens":12,"output_tokens":7}
		}`))
	}))
	t.Cleanup(server.Close)

	client := NewAnthropicClient(AnthropicConfig{
		Enabled:        true,
		APIKey:         "test-key",
		Model:          "claude-test",
		BaseURL:        server.URL,
		RequestTimeout: time.Second,
	})

	resp, err := client.CompleteStructured(context.Background(), StructuredRequest{
		System:    "system prompt",
		Prompt:    "user prompt",
		Schema:    schema,
		MaxTokens: 321,
	})

	require.NoError(t, err)
	require.Equal(t, json.RawMessage(rawOutput), resp.Raw)
	require.Equal(t, "claude-test", resp.Model)
	require.Equal(t, 12, resp.InputTokens)
	require.Equal(t, 7, resp.OutputTokens)
}

func TestAnthropicClientTransportErrorIsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	baseURL := server.URL
	server.Close()

	client := NewAnthropicClient(AnthropicConfig{
		Enabled:        true,
		APIKey:         "test-key",
		Model:          "claude-test",
		BaseURL:        baseURL,
		RequestTimeout: time.Second,
	})

	_, err := client.CompleteStructured(context.Background(), StructuredRequest{
		Prompt:    "prompt",
		Schema:    map[string]any{"type": "object"},
		MaxTokens: 64,
	})

	require.Error(t, err)
	require.ErrorIs(t, err, ErrOverloaded)
	require.NotErrorIs(t, err, ErrInvalidOutput)
}

func TestAnthropicClientDisabled(t *testing.T) {
	client := NewAnthropicClient(AnthropicConfig{Enabled: false})
	_, err := client.CompleteStructured(context.Background(), StructuredRequest{})
	require.ErrorIs(t, err, ErrDisabled)
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
