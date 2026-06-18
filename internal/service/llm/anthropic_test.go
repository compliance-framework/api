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
			name:     "request timeout",
			status:   http.StatusRequestTimeout,
			body:     `{"type":"error","error":{"type":"request_timeout_error","message":"try later"}}`,
			expected: ErrOverloaded,
		},
		{
			name:     "conflict",
			status:   http.StatusConflict,
			body:     `{"type":"error","error":{"type":"conflict_error","message":"try later"}}`,
			expected: ErrOverloaded,
		},
		{
			name:     "internal server error",
			status:   http.StatusInternalServerError,
			body:     `{"type":"error","error":{"type":"api_error","message":"try later"}}`,
			expected: ErrOverloaded,
		},
		{
			name:     "bad gateway",
			status:   http.StatusBadGateway,
			body:     `{"type":"error","error":{"type":"api_error","message":"try later"}}`,
			expected: ErrOverloaded,
		},
		{
			name:     "service unavailable",
			status:   http.StatusServiceUnavailable,
			body:     `{"type":"error","error":{"type":"api_error","message":"try later"}}`,
			expected: ErrOverloaded,
		},
		{
			name:     "gateway timeout",
			status:   http.StatusGatewayTimeout,
			body:     `{"type":"error","error":{"type":"api_error","message":"try later"}}`,
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
			"answer": map[string]any{"type": "string", "minLength": float64(2), "pattern": "^ok$"},
			"items": map[string]any{
				"type":      "array",
				"maxLength": float64(10),
				"items":     map[string]any{"type": "integer", "minimum": float64(1), "maximum": float64(5)},
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
		sanitizedSchema := format["schema"].(map[string]any)
		requireNoUnsupportedAnthropicSchemaKeywords(t, sanitizedSchema)
		require.Equal(t, "object", sanitizedSchema["type"])
		require.Equal(t, []any{"answer", "items"}, sanitizedSchema["required"])

		properties := sanitizedSchema["properties"].(map[string]any)
		require.Equal(t, map[string]any{"type": "string"}, properties["answer"])
		require.Equal(t, map[string]any{
			"type":  "array",
			"items": map[string]any{"type": "integer"},
		}, properties["items"])

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
	require.Equal(t, float64(2), schema["properties"].(map[string]any)["answer"].(map[string]any)["minLength"])
}

func TestAnthropicClientStructuredOutput(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		stopReason string
		wantErr    error
		wantEmpty  bool
		wantRaw    string
	}{
		{
			name:       "plain json",
			content:    `[{"type":"text","text":"{\"mappings\":[]}"}]`,
			stopReason: "end_turn",
			wantRaw:    `{"mappings":[]}`,
		},
		{
			name:       "fenced json",
			content:    `[{"type":"text","text":"` + "```json\\n{\\\"mappings\\\":[]}\\n```" + `"}]`,
			stopReason: "end_turn",
			wantRaw:    `{"mappings":[]}`,
		},
		{
			name:       "prose is empty output",
			content:    `[{"type":"text","text":"No mappings apply to this system."}]`,
			stopReason: "end_turn",
			wantEmpty:  true,
		},
		{
			name:       "no content is empty output",
			content:    `[]`,
			stopReason: "end_turn",
			wantEmpty:  true,
		},
		{
			name:       "truncated prose is an error",
			content:    `[{"type":"text","text":"Here are the mappings: {\"mappings\":[{\"control"}]`,
			stopReason: "max_tokens",
			wantErr:    ErrInvalidOutput,
		},
		{
			name:       "truncated with no content is an error",
			content:    `[]`,
			stopReason: "max_tokens",
			wantErr:    ErrInvalidOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"id":"msg_test",
					"type":"message",
					"role":"assistant",
					"model":"claude-test",
					"content":` + tt.content + `,
					"stop_reason":"` + tt.stopReason + `",
					"stop_sequence":"",
					"usage":{"input_tokens":5,"output_tokens":3}
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
				Prompt:    "prompt",
				Schema:    map[string]any{"type": "object"},
				MaxTokens: 64,
			})

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantEmpty, resp.EmptyOutput)
			if tt.wantEmpty {
				require.Nil(t, resp.Raw)
				// Token usage is still recorded for empty outputs.
				require.Equal(t, 5, resp.InputTokens)
			} else {
				require.Equal(t, json.RawMessage(tt.wantRaw), resp.Raw)
			}
		})
	}
}

func TestAnthropicClientTruncatedOutputCarriesRawText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"msg_test",
			"type":"message",
			"role":"assistant",
			"model":"claude-test",
			"content":[{"type":"text","text":"{\"mappings\":[{\"control_key\":\"cat:AC-1"}],
			"stop_reason":"max_tokens",
			"stop_sequence":"",
			"usage":{"input_tokens":10,"output_tokens":4096}
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

	_, err := client.CompleteStructured(context.Background(), StructuredRequest{
		Prompt:    "prompt",
		Schema:    map[string]any{"type": "object"},
		MaxTokens: 64,
	})

	require.ErrorIs(t, err, ErrInvalidOutput)
	var outErr *OutputError
	require.ErrorAs(t, err, &outErr)
	require.Equal(t, "max_tokens", outErr.StopReason)
	require.Equal(t, 4096, outErr.OutputTokens)
	require.Contains(t, outErr.Text, `"mappings"`)
}

func TestAnthropicClientRateLimitCarriesRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`))
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

	require.ErrorIs(t, err, ErrRateLimited)
	var rateLimit *RateLimitError
	require.ErrorAs(t, err, &rateLimit)
	require.Equal(t, 12*time.Second, rateLimit.RetryAfter)
}

func TestAnthropicClientAppliesCacheControl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))

		system := payload["system"].([]any)
		require.Len(t, system, 1)
		systemCache := system[0].(map[string]any)["cache_control"].(map[string]any)
		require.Equal(t, "ephemeral", systemCache["type"])
		require.Equal(t, "1h", systemCache["ttl"])

		messages := payload["messages"].([]any)
		require.Len(t, messages, 1)
		content := messages[0].(map[string]any)["content"].([]any)
		require.Len(t, content, 2)

		prefixCache := content[0].(map[string]any)["cache_control"].(map[string]any)
		require.Equal(t, "1h", prefixCache["ttl"])
		require.Equal(t, "controls", content[0].(map[string]any)["text"])

		// The volatile tail must stay uncached.
		_, volatileHasCache := content[1].(map[string]any)["cache_control"]
		require.False(t, volatileHasCache)
		require.Equal(t, "labels", content[1].(map[string]any)["text"])

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"msg_test",
			"type":"message",
			"role":"assistant",
			"model":"claude-test",
			"content":[{"type":"text","text":"{}"}],
			"stop_reason":"end_turn",
			"stop_sequence":"",
			"usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":40,"cache_creation_input_tokens":20}
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
		System:              "sys",
		SystemCacheTTL:      CacheTTL1h,
		CachedUserPrefix:    "controls",
		CachedUserPrefixTTL: CacheTTL1h,
		Prompt:              "labels",
		Schema:              map[string]any{"type": "object"},
		MaxTokens:           64,
	})

	require.NoError(t, err)
	require.Equal(t, 40, resp.CacheReadInputTokens)
	require.Equal(t, 20, resp.CacheCreationInputTokens)
}

func TestSanitizeAnthropicSchema(t *testing.T) {
	schema := map[string]any{
		"type":      "object",
		"maxLength": float64(20),
		"properties": map[string]any{
			"name": map[string]any{"type": "string", "minLength": float64(1), "pattern": ".+"},
			"scores": map[string]any{
				"type":        "array",
				"minItems":    float64(1),
				"maxItems":    float64(5),
				"uniqueItems": true,
				"items": []any{
					map[string]any{"type": "number", "minimum": float64(0), "multipleOf": float64(0.5)},
				},
			},
			"metadata": map[string]any{
				"type":          "object",
				"minProperties": float64(1),
				"maxProperties": float64(3),
				"properties": map[string]any{
					"source": map[string]any{"type": "string"},
				},
				"required": []any{"source"},
			},
		},
	}

	sanitized := sanitizeAnthropicSchema(schema)

	requireNoUnsupportedAnthropicSchemaKeywords(t, sanitized)
	require.Equal(t, map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
			"scores": map[string]any{
				"type":  "array",
				"items": []any{map[string]any{"type": "number"}},
			},
			"metadata": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"source": map[string]any{"type": "string"},
				},
				"required": []any{"source"},
			},
		},
	}, sanitized)
	require.Contains(t, schema, "maxLength")
	require.Contains(t, schema["properties"].(map[string]any)["name"].(map[string]any), "minLength")
}

func TestAnthropicClientMaxTokensDefaultAndOverride(t *testing.T) {
	tests := []struct {
		name     string
		request  int
		expected float64
	}{
		{name: "default", request: 0, expected: float64(DefaultAnthropicMaxTokens)},
		{name: "override", request: 123, expected: 123},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
				require.Equal(t, tt.expected, payload["max_tokens"])

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"id":"msg_test",
					"type":"message",
					"role":"assistant",
					"model":"claude-test",
					"content":[{"type":"text","text":"{}"}],
					"stop_reason":"end_turn",
					"stop_sequence":"",
					"usage":{"input_tokens":1,"output_tokens":1}
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

			_, err := client.CompleteStructured(context.Background(), StructuredRequest{
				Prompt:    "prompt",
				Schema:    map[string]any{"type": "object"},
				MaxTokens: tt.request,
			})

			require.NoError(t, err)
		})
	}
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

func TestAnthropicClientRequestTimeoutIsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(25 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"msg_test",
			"type":"message",
			"role":"assistant",
			"model":"claude-test",
			"content":[{"type":"text","text":"{}"}],
			"stop_reason":"end_turn",
			"stop_sequence":"",
			"usage":{"input_tokens":1,"output_tokens":1}
		}`))
	}))
	t.Cleanup(server.Close)

	client := NewAnthropicClient(AnthropicConfig{
		Enabled:        true,
		APIKey:         "test-key",
		Model:          "claude-test",
		BaseURL:        server.URL,
		RequestTimeout: time.Millisecond,
	})

	_, err := client.CompleteStructured(context.Background(), StructuredRequest{
		Prompt:    "prompt",
		Schema:    map[string]any{"type": "object"},
		MaxTokens: 64,
	})

	require.Error(t, err)
	require.ErrorIs(t, err, ErrOverloaded)
}

func TestAnthropicClientCallerCanceledContextPassesThrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)

	client := NewAnthropicClient(AnthropicConfig{
		Enabled:        true,
		APIKey:         "test-key",
		Model:          "claude-test",
		BaseURL:        server.URL,
		RequestTimeout: time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.CompleteStructured(ctx, StructuredRequest{
		Prompt:    "prompt",
		Schema:    map[string]any{"type": "object"},
		MaxTokens: 64,
	})

	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrOverloaded)
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

func requireNoUnsupportedAnthropicSchemaKeywords(t *testing.T, value any) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			_, unsupported := unsupportedAnthropicSchemaKeywords[key]
			require.Falsef(t, unsupported, "schema contains unsupported keyword %q", key)
			requireNoUnsupportedAnthropicSchemaKeywords(t, child)
		}
	case []any:
		for _, child := range typed {
			requireNoUnsupportedAnthropicSchemaKeywords(t, child)
		}
	}
}
