package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/compliance-framework/api/pkg/policyeval"
)

type PlaybackRequest = policyeval.EvaluateRequest
type PlaybackResponse = policyeval.EvaluateResponse

// PlaybackPolicyError is returned when the API rejects the policy itself (422): it does
// not parse, compile or evaluate, times out, or contains no compliance_framework package.
type PlaybackPolicyError struct {
	Errors []policyeval.EvalError
}

func (e *PlaybackPolicyError) Error() string {
	if len(e.Errors) == 0 {
		return "playback: policy rejected"
	}
	return fmt.Sprintf("playback: %s: %s", e.Errors[0].Code, e.Errors[0].Message)
}

type playbackClient struct {
	client *Client
}

// Evaluate runs a Rego policy against input on the API and returns the outcome.
func (p *playbackClient) Evaluate(ctx context.Context, req PlaybackRequest) (*PlaybackResponse, error) {
	response, err := p.client.doJSONRequest(ctx, http.MethodPost, "/api/playback/evaluate", req)
	if err != nil {
		return nil, err
	}
	defer closeResponseBody(response, p.client.config.Logger)

	switch response.StatusCode {
	case http.StatusOK:
		var out PlaybackResponse
		if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("decode playback response: %w", err)
		}
		return &out, nil
	case http.StatusUnprocessableEntity:
		var out policyeval.ErrorResponse
		if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("decode playback error response: %w", err)
		}
		return nil, &PlaybackPolicyError{Errors: out.Errors}
	default:
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return nil, fmt.Errorf("unexpected api response status code: %d: %s", response.StatusCode, body)
	}
}
