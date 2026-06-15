package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

	params := anthropic.MessageNewParams{
		MaxTokens: int64(maxTokens),
		Model:     anthropic.Model(c.model),
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(req.Prompt)),
		},
		OutputConfig: anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: sanitizeAnthropicSchema(req.Schema)},
		},
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: req.System}}
	}

	msg, err := c.client.Messages.New(callCtx, params, option.WithRequestTimeout(c.requestTimeout), option.WithMaxRetries(0))
	if err != nil {
		return nil, mapAnthropicError(ctx, callCtx, err)
	}

	raw, err := structuredRawJSON(msg)
	if err != nil {
		return nil, err
	}

	return &StructuredResponse{
		Raw:          raw,
		Model:        string(msg.Model),
		InputTokens:  int(msg.Usage.InputTokens),
		OutputTokens: int(msg.Usage.OutputTokens),
	}, nil
}

func structuredRawJSON(msg *anthropic.Message) (json.RawMessage, error) {
	if msg == nil {
		return nil, fmt.Errorf("%w: empty provider response", ErrInvalidOutput)
	}
	for _, block := range msg.Content {
		if block.Type == "text" {
			raw := json.RawMessage(block.Text)
			if !json.Valid(raw) {
				return nil, fmt.Errorf("%w: provider returned non-json text content", ErrInvalidOutput)
			}
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%w: provider response did not contain text json", ErrInvalidOutput)
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
			return fmt.Errorf("%w: %v", ErrRateLimited, err)
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
