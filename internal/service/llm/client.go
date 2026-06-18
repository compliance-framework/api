package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Client interface {
	// CompleteStructured sends system+user prompts and a JSON schema the
	// response must conform to. Returns raw schema-constrained JSON.
	CompleteStructured(ctx context.Context, req StructuredRequest) (*StructuredResponse, error)
}

// CacheTTL controls prompt-cache breakpoints. The empty value disables caching
// for that block; "5m" and "1h" map to Anthropic's ephemeral cache lifetimes.
type CacheTTL string

const (
	CacheTTLNone CacheTTL = ""
	CacheTTL5m   CacheTTL = "5m"
	CacheTTL1h   CacheTTL = "1h"
)

type StructuredRequest struct {
	System    string
	Prompt    string
	Schema    map[string]any // JSON Schema for the output object
	MaxTokens int

	// Prompt caching (additive; zero values preserve the uncached behaviour).
	// SystemCacheTTL sets a cache breakpoint at the end of the system block.
	SystemCacheTTL CacheTTL
	// CachedUserPrefix, when non-empty, is emitted as a user text block before
	// Prompt with its own cache breakpoint. Use it for the large, stable portion
	// of the user content so the volatile tail in Prompt stays uncached.
	CachedUserPrefix    string
	CachedUserPrefixTTL CacheTTL
}

type StructuredResponse struct {
	Raw json.RawMessage
	// EmptyOutput is true when the provider returned no structured JSON output
	// (e.g. a plain-text "nothing applies" message) rather than a schema-shaped
	// payload. Raw is nil in that case. Callers should treat this as a valid
	// "no result" outcome, not a failure. It is distinct from a truncated
	// response, which surfaces as ErrInvalidOutput so it can be retried.
	EmptyOutput  bool
	Model        string
	InputTokens  int
	OutputTokens int
	// Prompt-cache accounting; cache reads do not count against ITPM rate limits
	// for most models, so these are useful for verifying caching is effective.
	CacheReadInputTokens     int
	CacheCreationInputTokens int
}

var (
	ErrDisabled      = errors.New("llm: disabled by configuration")
	ErrAuth          = errors.New("llm: authentication failed")
	ErrRateLimited   = errors.New("llm: rate limited")
	ErrOverloaded    = errors.New("llm: provider overloaded")
	ErrInvalidOutput = errors.New("llm: output did not match schema")
)

// RateLimitError wraps a provider 429 and carries the Retry-After hint (zero
// when the provider did not supply one). It unwraps to ErrRateLimited so
// existing errors.Is(err, ErrRateLimited) checks keep working.
type RateLimitError struct {
	RetryAfter time.Duration
	Err        error
}

func (e *RateLimitError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", ErrRateLimited.Error(), e.Err)
	}
	return ErrRateLimited.Error()
}

func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// OutputError carries diagnostic detail about an invalid or truncated structured
// response so callers can log what the provider actually returned (e.g. the
// truncated JSON) instead of just the generic schema-mismatch message. It
// unwraps to ErrInvalidOutput so existing errors.Is checks keep working.
type OutputError struct {
	Reason       string
	StopReason   string
	OutputTokens int
	// Text is the raw provider text content (possibly truncated JSON or prose).
	Text string
}

func (e *OutputError) Error() string {
	return fmt.Sprintf("%s: %s", ErrInvalidOutput.Error(), e.Reason)
}

func (e *OutputError) Unwrap() error { return ErrInvalidOutput }
