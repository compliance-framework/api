package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DriverAuthzen is the name of the remote AuthZen HTTP driver: it turns any
// AuthZen-compliant PDP (Topaz, Axiomatics, PlainID, …) into CCF's decision engine by
// changing one config key. See the design plan §3.3 (Phase 3).
const DriverAuthzen = "authzen"

// defaultAuthzenTimeout bounds a single PDP call so a hung PDP can't stall a request when
// the caller's context carries no deadline of its own.
const defaultAuthzenTimeout = 5 * time.Second

func init() {
	Register(DriverAuthzen, func(opts Options, deps Deps) (PDP, error) {
		return NewAuthZen(opts.Endpoint, deps.Logger)
	})
}

// AuthZen is a PDP that delegates decisions to a remote AuthZen Authorization API. It
// supplies facts only (the PEP and handlers build the tuple) and holds no policy logic.
// It is safe for concurrent use (the underlying http.Client is).
type AuthZen struct {
	evalURL      string // single Access Evaluation endpoint
	evalsURL     string // batch Access Evaluations endpoint
	wellKnownURL string // AuthZen metadata, used for the health check
	client       *http.Client
	logger       *zap.SugaredLogger
}

// NewAuthZen constructs the driver from the PDP's single-evaluation URL. The batch URL is
// derived by AuthZen convention; an empty or malformed endpoint is a startup error.
func NewAuthZen(endpoint string, logger *zap.SugaredLogger) (*AuthZen, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, errors.New("authz: authzen driver requires authz.endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("authz: invalid authz.endpoint %q", endpoint)
	}
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &AuthZen{
		evalURL:      endpoint,
		evalsURL:     deriveEvaluationsURL(endpoint),
		wellKnownURL: u.Scheme + "://" + u.Host + "/.well-known/authzen-configuration",
		client:       &http.Client{Timeout: defaultAuthzenTimeout},
		logger:       logger,
	}, nil
}

// deriveEvaluationsURL maps the single-evaluation URL to its batch sibling using the
// AuthZen path convention (/access/v1/evaluation → /access/v1/evaluations). It operates on
// the parsed path so a trailing slash or a query string doesn't defeat the match, and the
// query is preserved. PDPs that serve both at one path still work: any path that isn't a
// /evaluation suffix returns the original URL unchanged.
func deriveEvaluationsURL(eval string) string {
	u, err := url.Parse(eval)
	if err != nil {
		return eval
	}
	p := strings.TrimSuffix(u.Path, "/")
	if strings.HasSuffix(p, "/evaluation") {
		u.Path = strings.TrimSuffix(p, "/evaluation") + "/evaluations"
		return u.String()
	}
	return eval
}

// --- AuthZen wire shapes (Authorization API) ---

type authzenSubject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authzenAction struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authzenResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authzenEvaluation struct {
	Subject  authzenSubject  `json:"subject"`
	Action   authzenAction   `json:"action"`
	Resource authzenResource `json:"resource"`
	Context  map[string]any  `json:"context,omitempty"`
}

type authzenDecisionResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

type authzenEvaluationsRequest struct {
	Evaluations []authzenEvaluation `json:"evaluations"`
}

type authzenEvaluationsResponse struct {
	Evaluations []authzenDecisionResponse `json:"evaluations"`
}

func toEvaluation(s Subject, action string, r Resource, reqCtx map[string]any) authzenEvaluation {
	return authzenEvaluation{
		Subject:  authzenSubject{Type: s.Type, ID: s.ID, Properties: s.Props},
		Action:   authzenAction{Name: action},
		Resource: authzenResource{Type: r.Type, ID: r.ID, Properties: r.Props},
		Context:  reqCtx,
	}
}

// decisionFrom maps an AuthZen response to a CCF Decision. AuthZen carries an optional
// context object; a "reason" string there is surfaced for logging only.
func decisionFrom(resp authzenDecisionResponse) Decision {
	reason := ""
	if r, ok := resp.Context["reason"].(string); ok {
		reason = r
	}
	return Decision{Allow: resp.Decision, Reason: reason}
}

// Evaluate implements PDP via the AuthZen single Access Evaluation API.
func (a *AuthZen) Evaluate(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error) {
	var resp authzenDecisionResponse
	if err := a.post(ctx, a.evalURL, toEvaluation(s, action, r, reqCtx), &resp); err != nil {
		return Decision{}, err
	}
	return decisionFrom(resp), nil
}

// Evaluations implements PDP via the AuthZen batch Access Evaluations API — one HTTP call
// for the whole batch (list filtering / UI permission hints), not N calls.
func (a *AuthZen) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	if len(reqs) == 0 {
		return []Decision{}, nil
	}
	body := authzenEvaluationsRequest{Evaluations: make([]authzenEvaluation, len(reqs))}
	for i, req := range reqs {
		body.Evaluations[i] = toEvaluation(req.Subject, req.Action, req.Resource, req.Context)
	}
	var resp authzenEvaluationsResponse
	if err := a.post(ctx, a.evalsURL, body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Evaluations) != len(reqs) {
		return nil, fmt.Errorf("authz: authzen returned %d decisions for %d requests", len(resp.Evaluations), len(reqs))
	}
	out := make([]Decision, len(reqs))
	for i, d := range resp.Evaluations {
		out[i] = decisionFrom(d)
	}
	return out, nil
}

// Health implements Healther by probing the PDP's AuthZen metadata document. A reachable
// 2xx means the engine is up; anything else is reported as unavailable.
func (a *AuthZen) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.wellKnownURL, nil)
	if err != nil {
		return fmt.Errorf("authz: build authzen health request: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("authz: authzen PDP unreachable (%v): %w", err, ErrUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("authz: authzen PDP health returned %s: %w", resp.Status, ErrUnavailable)
	}
	return nil
}

// post sends payload as JSON to endpoint and decodes a JSON response into out. It maps
// transport failures, timeouts, 429 and 5xx to ErrUnavailable (the PEP then applies the
// configured fail mode); other non-2xx statuses are plain errors (the PEP maps them to
// 500), since a compliant PDP returns its allow/deny verdict as a 200 body.
func (a *AuthZen) post(ctx context.Context, endpoint string, payload any, out any) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("authz: marshal authzen request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("authz: build authzen request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("authz: authzen request to %s failed (%v): %w", endpoint, err, ErrUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// proceed to decode
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("authz: authzen PDP %s returned %s: %w", endpoint, resp.Status, ErrUnavailable)
	default:
		return fmt.Errorf("authz: authzen PDP %s returned %s: %s", endpoint, resp.Status, readSnippet(resp.Body))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("authz: decode authzen response from %s: %w", endpoint, err)
	}
	// Drain any trailing bytes (e.g. a newline after the JSON value) so net/http can return
	// the connection to the keep-alive pool instead of re-handshaking on the next decision.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// readSnippet returns a short, trimmed prefix of an error response body for logs.
func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	return strings.TrimSpace(string(b))
}
