package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
)

const (
	agentConfigPath = "/api/agent/config"

	// apiStatusErrorBodyLimit caps how much of an unexpected response body is kept in an
	// APIStatusError.
	apiStatusErrorBodyLimit = 4 << 10
)

var (
	// ErrRemoteConfigUnsupported is returned when the API answers 404 on a remote agent
	// configuration route, meaning the API predates the feature.
	ErrRemoteConfigUnsupported = errors.New("sdk: api does not support remote agent configuration")

	// ErrAgentAuthRequired is returned, without making a request, when the client has no agent
	// credentials (Config.AgentAuth). The remote configuration routes accept agent JWTs only.
	ErrAgentAuthRequired = errors.New("sdk: remote agent configuration requires agent credentials")
)

// APIStatusError is returned for any non-2xx response that has no dedicated sentinel error.
// Callers map specific statuses (401, 403, 409, 413, ...) from StatusCode.
type APIStatusError struct {
	// StatusCode is the HTTP status code of the response.
	StatusCode int
	// Body is the response body, truncated to at most 4 KiB.
	Body string
}

// Error implements error. It includes the status code and the (truncated) response body.
func (e *APIStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("sdk: unexpected api response status code: %d", e.StatusCode)
	}
	return fmt.Sprintf("sdk: unexpected api response status code: %d: %s", e.StatusCode, e.Body)
}

// AgentConfigResult is the outcome of AgentConfig.Get.
type AgentConfigResult struct {
	// Document is the current overlay document; nil when NotModified is true.
	Document *agentconfig.OverlayDocument
	// NotModified is true when the API answered 304 to the presented If-None-Match.
	NotModified bool
	// ETag is the raw ETag response header. Store it and send it back verbatim as
	// If-None-Match (R7); never construct one. On a 304 without an ETag header it is the
	// If-None-Match value that was sent.
	ETag string
}

type agentConfigClient struct {
	client *Client
}

// Get fetches the agent's remote configuration overlay (GET /api/agent/config).
//
// When ifNoneMatch is non-empty it is sent verbatim as the If-None-Match header; pass the raw
// ETag of a previous result. A 200 returns the decoded document and its ETag, a 304 returns
// NotModified. A 404 yields ErrRemoteConfigUnsupported and any other non-2xx an
// *APIStatusError. Requires agent credentials, otherwise ErrAgentAuthRequired is returned
// without making a request.
func (a *agentConfigClient) Get(ctx context.Context, ifNoneMatch string) (*AgentConfigResult, error) {
	if !a.client.hasAgentAuth() {
		return nil, ErrAgentAuthRequired
	}

	var headers http.Header
	if ifNoneMatch != "" {
		headers = http.Header{}
		// Set the value directly so it is sent exactly as given.
		headers["If-None-Match"] = []string{ifNoneMatch}
	}

	resp, err := a.client.doRequestWithHeaders(ctx, http.MethodGet, agentConfigPath, nil, headers)
	if err != nil {
		return nil, err
	}
	defer closeResponseBody(resp, a.client.config.Logger)

	switch resp.StatusCode {
	case http.StatusNotModified:
		etag := resp.Header.Get("ETag")
		if etag == "" {
			etag = ifNoneMatch
		}
		return &AgentConfigResult{NotModified: true, ETag: etag}, nil
	case http.StatusOK:
		var body struct {
			Data *agentconfig.OverlayDocument `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, fmt.Errorf("sdk: decode agent config response: %w", err)
		}
		if body.Data == nil {
			return nil, errors.New("sdk: agent config response missing data")
		}
		return &AgentConfigResult{Document: body.Data, ETag: resp.Header.Get("ETag")}, nil
	case http.StatusNotFound:
		return nil, ErrRemoteConfigUnsupported
	default:
		return nil, newAPIStatusError(resp)
	}
}

// Report submits this instance's configuration report
// (PUT /api/agent/instances/<instanceID>/config-report).
//
// Any 2xx (normally 204) returns nil. A 404 yields ErrRemoteConfigUnsupported and any other
// non-2xx an *APIStatusError. There are no retries beyond the client's single 401
// token-refresh retry; the agent owns the reporting cadence. Requires agent credentials,
// otherwise ErrAgentAuthRequired is returned without making a request.
func (a *agentConfigClient) Report(ctx context.Context, instanceID uuid.UUID, r agentconfig.Report) error {
	if !a.client.hasAgentAuth() {
		return ErrAgentAuthRequired
	}

	path := fmt.Sprintf("/api/agent/instances/%s/config-report", instanceID)
	resp, err := a.client.doJSONRequest(ctx, http.MethodPut, path, r)
	if err != nil {
		return err
	}
	defer closeResponseBody(resp, a.client.config.Logger)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return ErrRemoteConfigUnsupported
	default:
		return newAPIStatusError(resp)
	}
}

// newAPIStatusError builds an APIStatusError from resp, reading at most
// apiStatusErrorBodyLimit bytes of its body.
func newAPIStatusError(resp *http.Response) *APIStatusError {
	e := &APIStatusError{StatusCode: resp.StatusCode}
	if resp.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, apiStatusErrorBodyLimit))
		e.Body = string(body)
	}
	return e
}
