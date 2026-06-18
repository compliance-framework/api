package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const (
	DefaultAnthropicModel          = "claude-opus-4-8"
	DefaultAnthropicRequestTimeout = 120 * time.Second
	DefaultAnthropicMaxTokens      = 4096
)

var unsupportedAnthropicSchemaKeywords = map[string]struct{}{
	"minimum":          {},
	"maximum":          {},
	"exclusiveMinimum": {},
	"exclusiveMaximum": {},
	"multipleOf":       {},
	"minLength":        {},
	"maxLength":        {},
	"pattern":          {},
	"minItems":         {},
	"maxItems":         {},
	"uniqueItems":      {},
	"minProperties":    {},
	"maxProperties":    {},
}

type AnthropicConfig struct {
	Enabled        bool
	APIKey         string
	Model          string
	BaseURL        string
	RequestTimeout time.Duration
}

type AnthropicClient struct {
	enabled        bool
	apiKey         string
	model          string
	requestTimeout time.Duration
	client         anthropic.Client
}

func NewAnthropicClient(cfg AnthropicConfig) *AnthropicClient {
	model := cfg.Model
	if model == "" {
		model = DefaultAnthropicModel
	}
	requestTimeout := cfg.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = DefaultAnthropicRequestTimeout
	}

	opts := []option.RequestOption{
		option.WithoutEnvironmentDefaults(),
		option.WithRequestTimeout(requestTimeout),
		option.WithMaxRetries(0),
	}
	if cfg.APIKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.APIKey))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}

	return &AnthropicClient{
		enabled:        cfg.Enabled,
		apiKey:         cfg.APIKey,
		model:          model,
		requestTimeout: requestTimeout,
		client:         anthropic.NewClient(opts...),
	}
}

func (c *AnthropicClient) CompleteStructured(ctx context.Context, req StructuredRequest) (*StructuredResponse, error) {
	if !c.enabled {
		return nil, ErrDisabled
	}
	if c.apiKey == "" {
		return nil, fmt.Errorf("%w: api key is required", ErrAuth)
	}

	callCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = DefaultAnthropicMaxTokens
	}

	// Build the user message as one or two text blocks. A non-empty cached
	// prefix is sent first with its own cache breakpoint so the volatile tail in
	// req.Prompt stays uncached.
	userBlocks := make([]anthropic.ContentBlockParamUnion, 0, 2)
	if req.CachedUserPrefix != "" {
		prefix := anthropic.NewTextBlock(req.CachedUserPrefix)
		prefix.OfText.CacheControl = cacheControlParam(req.CachedUserPrefixTTL)
		userBlocks = append(userBlocks, prefix)
	}
	userBlocks = append(userBlocks, anthropic.NewTextBlock(req.Prompt))

	params := anthropic.MessageNewParams{
		MaxTokens: int64(maxTokens),
		Model:     anthropic.Model(c.model),
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(userBlocks...),
		},
		OutputConfig: anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: sanitizeAnthropicSchema(req.Schema)},
		},
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{
			Text:         req.System,
			CacheControl: cacheControlParam(req.SystemCacheTTL),
		}}
	}

	msg, err := c.client.Messages.New(callCtx, params, option.WithRequestTimeout(c.requestTimeout), option.WithMaxRetries(0))
	if err != nil {
		return nil, mapAnthropicError(ctx, callCtx, err)
	}

	raw, empty, err := structuredRawJSON(msg)
	if err != nil {
		return nil, err
	}

	return &StructuredResponse{
		Raw:                      raw,
		EmptyOutput:              empty,
		Model:                    string(msg.Model),
		InputTokens:              int(msg.Usage.InputTokens),
		OutputTokens:             int(msg.Usage.OutputTokens),
		CacheReadInputTokens:     int(msg.Usage.CacheReadInputTokens),
		CacheCreationInputTokens: int(msg.Usage.CacheCreationInputTokens),
	}, nil
}

// cacheControlParam maps a CacheTTL to the SDK cache-control param. The empty
// TTL returns the zero value, which the SDK omits (no cache breakpoint).
func cacheControlParam(ttl CacheTTL) anthropic.CacheControlEphemeralParam {
	switch ttl {
	case CacheTTL5m:
		cc := anthropic.NewCacheControlEphemeralParam()
		cc.TTL = anthropic.CacheControlEphemeralTTLTTL5m
		return cc
	case CacheTTL1h:
		cc := anthropic.NewCacheControlEphemeralParam()
		cc.TTL = anthropic.CacheControlEphemeralTTLTTL1h
		return cc
	default:
		return anthropic.CacheControlEphemeralParam{}
	}
}

// structuredRawJSON extracts the schema-shaped JSON from a provider message.
//
// It returns (raw, false, nil) for a normal JSON payload. When the model emits
// plain text instead of JSON (e.g. "no mappings apply"), or returns no content
// at all, it returns (nil, true, nil) to signal a legitimate empty result so
// the caller can record "no output" rather than failing. A truncated response
// (StopReason == max_tokens) is reported as ErrInvalidOutput so it can be
// retried, since the JSON was likely cut off mid-stream.
func structuredRawJSON(msg *anthropic.Message) (json.RawMessage, bool, error) {
	if msg == nil {
		return nil, false, fmt.Errorf("%w: empty provider response", ErrInvalidOutput)
	}

	truncated := msg.StopReason == anthropic.StopReasonMaxTokens

	for _, block := range msg.Content {
		if block.Type != "text" {
			continue
		}
		if raw, ok := extractJSONObject(block.Text); ok {
			return raw, false, nil
		}
		// A text block that is not (and does not contain) valid JSON. If the
		// model ran out of tokens the JSON was truncated and should be retried;
		// otherwise the model declined to produce structured output, which is a
		// valid empty result for our callers.
		if truncated {
			return nil, false, &OutputError{
				Reason:       "provider returned truncated non-json text content",
				StopReason:   string(msg.StopReason),
				OutputTokens: int(msg.Usage.OutputTokens),
				Text:         block.Text,
			}
		}
		return nil, true, nil
	}

	// No text content at all. Truncation before any content is an error; an
	// otherwise empty response is treated as no structured output.
	if truncated {
		return nil, false, &OutputError{
			Reason:       "provider response truncated before any content",
			StopReason:   string(msg.StopReason),
			OutputTokens: int(msg.Usage.OutputTokens),
		}
	}
	return nil, true, nil
}

// extractJSONObject returns the JSON payload from a text block, tolerating
// surrounding whitespace and markdown code fences (```json ... ```). It returns
// ok=false when the text does not contain a valid JSON document.
func extractJSONObject(text string) (json.RawMessage, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, false
	}
	if fenced, ok := stripCodeFence(trimmed); ok {
		trimmed = strings.TrimSpace(fenced)
	}
	if json.Valid([]byte(trimmed)) {
		return json.RawMessage(trimmed), true
	}
	return nil, false
}

// stripCodeFence removes a single leading/trailing markdown code fence, with an
// optional language tag on the opening fence (```json). It returns ok=false when
// the text is not fenced.
func stripCodeFence(text string) (string, bool) {
	if !strings.HasPrefix(text, "```") {
		return "", false
	}
	rest := strings.TrimPrefix(text, "```")
	if idx := strings.IndexByte(rest, '\n'); idx >= 0 {
		// Drop the remainder of the opening fence line (e.g. the "json" tag).
		rest = rest[idx+1:]
	} else {
		rest = ""
	}
	if end := strings.LastIndex(rest, "```"); end >= 0 {
		return rest[:end], true
	}
	return "", false
}

func sanitizeAnthropicSchema(schema map[string]any) map[string]any {
	sanitized, _ := sanitizeAnthropicSchemaValue(schema).(map[string]any)
	return sanitized
}

func sanitizeAnthropicSchemaValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		sanitized := make(map[string]any, len(typed))
		for key, child := range typed {
			if _, unsupported := unsupportedAnthropicSchemaKeywords[key]; unsupported {
				continue
			}
			sanitized[key] = sanitizeAnthropicSchemaValue(child)
		}
		return sanitized
	case []any:
		sanitized := make([]any, len(typed))
		for i, child := range typed {
			sanitized[i] = sanitizeAnthropicSchemaValue(child)
		}
		return sanitized
	default:
		return value
	}
}

func mapAnthropicError(ctx context.Context, callCtx context.Context, err error) error {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: %v", ErrAuth, err)
		case http.StatusBadRequest:
			// Unsupported structured-output validation constraints are stripped before
			// sending; malformed or otherwise rejected schemas are still invalid input.
			return fmt.Errorf("%w: %v", ErrInvalidOutput, err)
		case http.StatusTooManyRequests:
			return &RateLimitError{RetryAfter: retryAfterFromResponse(apiErr.Response), Err: err}
		case 529:
			return fmt.Errorf("%w: %v", ErrOverloaded, err)
		case http.StatusRequestTimeout, http.StatusConflict:
			return fmt.Errorf("%w: %v", ErrOverloaded, err)
		}
		if apiErr.StatusCode >= 500 {
			return fmt.Errorf("%w: %v", ErrOverloaded, err)
		}
		return err
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if parentErr := ctx.Err(); parentErr != nil {
			return parentErr
		}
		if callCtx.Err() != nil {
			return fmt.Errorf("%w: %v", ErrOverloaded, err)
		}
		return err
	}
	if strings.HasPrefix(err.Error(), "error parsing response json:") {
		return fmt.Errorf("%w: %v", ErrInvalidOutput, err)
	}
	return fmt.Errorf("%w: %v", ErrOverloaded, err)
}

// retryAfterFromResponse reads the Retry-After header (integer seconds or an
// HTTP-date) from a 429 response. It returns 0 when the header is absent or
// unparseable so callers can fall back to a default backoff.
func retryAfterFromResponse(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	value := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
