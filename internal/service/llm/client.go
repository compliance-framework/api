package llm

import (
	"context"
	"encoding/json"
	"errors"
)

type Client interface {
	// CompleteStructured sends system+user prompts and a JSON schema the
	// response must conform to. Returns raw schema-constrained JSON.
	CompleteStructured(ctx context.Context, req StructuredRequest) (*StructuredResponse, error)
}

type StructuredRequest struct {
	System    string
	Prompt    string
	Schema    map[string]any // JSON Schema for the output object
	MaxTokens int
}

type StructuredResponse struct {
	Raw          json.RawMessage
	Model        string
	InputTokens  int
	OutputTokens int
}

var (
	ErrDisabled      = errors.New("llm: disabled by configuration")
	ErrAuth          = errors.New("llm: authentication failed")
	ErrRateLimited   = errors.New("llm: rate limited")
	ErrOverloaded    = errors.New("llm: provider overloaded")
	ErrInvalidOutput = errors.New("llm: output did not match schema")
)
