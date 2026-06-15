package llm

import (
	"context"
	"encoding/json"
	"sync"
)

type FakeClient struct {
	mu sync.Mutex

	Raw          json.RawMessage
	Model        string
	InputTokens  int
	OutputTokens int
	Err          error
	Requests     []StructuredRequest
	Responses    []*StructuredResponse
	Errors       []error
}

func (f *FakeClient) CompleteStructured(ctx context.Context, req StructuredRequest) (*StructuredResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Requests = append(f.Requests, req)
	index := len(f.Requests) - 1
	if index < len(f.Errors) && f.Errors[index] != nil {
		return nil, f.Errors[index]
	}
	if index < len(f.Responses) && f.Responses[index] != nil {
		return f.Responses[index], nil
	}
	if f.Err != nil {
		return nil, f.Err
	}
	return &StructuredResponse{
		Raw:          f.Raw,
		Model:        f.Model,
		InputTokens:  f.InputTokens,
		OutputTokens: f.OutputTokens,
	}, nil
}
