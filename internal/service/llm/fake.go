package llm

import (
	"context"
	"encoding/json"
)

type FakeClient struct {
	Raw          json.RawMessage
	Model        string
	InputTokens  int
	OutputTokens int
	Err          error
	Requests     []StructuredRequest
}

func (f *FakeClient) CompleteStructured(ctx context.Context, req StructuredRequest) (*StructuredResponse, error) {
	f.Requests = append(f.Requests, req)
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
