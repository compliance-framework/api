package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
)

const testAgentETag = `W/"r7-0b7f1c2e-3d4a-4b5c-8d9e-0f1a2b3c4d5e"`

// agentConfigTestServer serves the agent token endpoint and delegates everything else to
// handler. It counts token fetches and non-token requests.
type agentConfigTestServer struct {
	*httptest.Server
	tokenRequests atomic.Int32
	requests      atomic.Int32
}

func newAgentConfigTestServer(t *testing.T, handler http.HandlerFunc) *agentConfigTestServer {
	t.Helper()
	s := &agentConfigTestServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/agent/token" {
			n := s.tokenRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"bearer","expires_in":3600}`, n)
			return
		}
		s.requests.Add(1)
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *agentConfigTestServer) client(withAuth bool) *Client {
	cfg := &Config{BaseURL: s.URL}
	if withAuth {
		cfg.AgentAuth = &AgentAuthConfig{ClientID: "client-id", ClientSecret: "client-secret"}
	}
	return NewClient(s.Client(), cfg)
}

func TestAgentConfigGetSendsIfNoneMatchVerbatimAndDecodes200(t *testing.T) {
	var (
		gotMethod, gotPath, gotINM, gotAuth string
		inmValues                           []string
	)
	created := time.Date(2026, time.September, 30, 10, 0, 0, 0, time.UTC)
	srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotINM = r.Header.Get("If-None-Match")
		inmValues = r.Header.Values("If-None-Match")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("ETag", `"r8-11111111-1111-1111-1111-111111111111"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"revision":8,"overlay":{"plugins":{"ssh":{"config":{"port":"2222"}}}},"created-at":"2026-09-30T10:00:00Z"}}`)
	})

	res, err := srv.client(true).AgentConfig.Get(context.Background(), testAgentETag)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/api/agent/config" {
		t.Fatalf("unexpected request %s %s", gotMethod, gotPath)
	}
	if gotINM != testAgentETag || len(inmValues) != 1 {
		t.Fatalf("If-None-Match not sent verbatim: got %q (%v)", gotINM, inmValues)
	}
	if gotAuth != "Bearer token-1" {
		t.Fatalf("unexpected Authorization %q", gotAuth)
	}
	if res.NotModified {
		t.Fatal("expected NotModified=false")
	}
	if res.ETag != `"r8-11111111-1111-1111-1111-111111111111"` {
		t.Fatalf("unexpected ETag %q", res.ETag)
	}
	if res.Document == nil || res.Document.Revision != 8 {
		t.Fatalf("unexpected document %+v", res.Document)
	}
	if res.Document.CreatedAt == nil || !res.Document.CreatedAt.Equal(created) {
		t.Fatalf("unexpected created-at %v", res.Document.CreatedAt)
	}
	var overlay map[string]any
	if err := json.Unmarshal(res.Document.Overlay, &overlay); err != nil {
		t.Fatalf("overlay not valid JSON: %v", err)
	}
	if _, ok := overlay["plugins"]; !ok {
		t.Fatalf("overlay missing plugins: %s", res.Document.Overlay)
	}
}

func TestAgentConfigGetOmitsIfNoneMatchWhenEmpty(t *testing.T) {
	var present bool
	srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["If-None-Match"]
		w.Header().Set("ETag", `"r0-22222222-2222-2222-2222-222222222222"`)
		_, _ = io.WriteString(w, `{"data":{"revision":0,"overlay":{}}}`)
	})

	res, err := srv.client(true).AgentConfig.Get(context.Background(), "")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if present {
		t.Fatal("If-None-Match must not be sent when empty")
	}
	if res.Document == nil || res.Document.Revision != 0 || res.Document.CreatedAt != nil {
		t.Fatalf("unexpected document %+v", res.Document)
	}
}

func TestAgentConfigGetNotModified(t *testing.T) {
	t.Run("with etag header", func(t *testing.T) {
		srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"r7-server"`)
			w.WriteHeader(http.StatusNotModified)
		})
		res, err := srv.client(true).AgentConfig.Get(context.Background(), testAgentETag)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if !res.NotModified || res.Document != nil || res.ETag != `"r7-server"` {
			t.Fatalf("unexpected result %+v", res)
		}
	})
	t.Run("without etag header", func(t *testing.T) {
		srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotModified)
		})
		res, err := srv.client(true).AgentConfig.Get(context.Background(), testAgentETag)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if !res.NotModified || res.Document != nil || res.ETag != testAgentETag {
			t.Fatalf("unexpected result %+v", res)
		}
	})
}

func TestAgentConfigGetNotFoundIsUnsupported(t *testing.T) {
	srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	res, err := srv.client(true).AgentConfig.Get(context.Background(), "")
	if !errors.Is(err, ErrRemoteConfigUnsupported) {
		t.Fatalf("expected ErrRemoteConfigUnsupported, got %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil result, got %+v", res)
	}
}

func TestAgentConfigGetOtherStatusIsAPIStatusError(t *testing.T) {
	srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errors":{"body":"boom"}}`+strings.Repeat("x", 8<<10))
	})
	_, err := srv.client(true).AgentConfig.Get(context.Background(), "")
	var apiErr *APIStatusError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIStatusError, got %T %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("unexpected status %d", apiErr.StatusCode)
	}
	if !strings.HasPrefix(apiErr.Body, `{"errors":{"body":"boom"}}`) || len(apiErr.Body) != 4<<10 {
		t.Fatalf("unexpected body (len %d): %.64q", len(apiErr.Body), apiErr.Body)
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error should include status and body: %q", err.Error())
	}
}

func TestAgentConfigGetRetriesOnceOn401KeepingHeaders(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []struct{ auth, inm string }
	)
	srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, struct{ auth, inm string }{r.Header.Get("Authorization"), r.Header.Get("If-None-Match")})
		n := len(calls)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	})

	res, err := srv.client(true).AgentConfig.Get(context.Background(), testAgentETag)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !res.NotModified {
		t.Fatalf("expected NotModified, got %+v", res)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 config requests, got %d", len(calls))
	}
	if got := srv.tokenRequests.Load(); got != 2 {
		t.Fatalf("expected 2 token requests, got %d", got)
	}
	if calls[0].auth != "Bearer token-1" || calls[1].auth != "Bearer token-2" {
		t.Fatalf("unexpected Authorization headers %+v", calls)
	}
	for i, c := range calls {
		if c.inm != testAgentETag {
			t.Fatalf("request %d If-None-Match = %q, want %q", i, c.inm, testAgentETag)
		}
	}
}

func TestAgentConfigRequiresAgentAuth(t *testing.T) {
	srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	c := srv.client(false)

	if _, err := c.AgentConfig.Get(context.Background(), testAgentETag); !errors.Is(err, ErrAgentAuthRequired) {
		t.Fatalf("Get: expected ErrAgentAuthRequired, got %v", err)
	}
	if err := c.AgentConfig.Report(context.Background(), uuid.New(), agentconfig.Report{}); !errors.Is(err, ErrAgentAuthRequired) {
		t.Fatalf("Report: expected ErrAgentAuthRequired, got %v", err)
	}
	if n := srv.requests.Load() + srv.tokenRequests.Load(); n != 0 {
		t.Fatalf("expected no HTTP requests, got %d", n)
	}
}

func TestAgentConfigReport(t *testing.T) {
	instanceID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	applied := int64(6)
	attempted := int64(7)
	report := agentconfig.Report{
		Hostname:          "ip-10-0-1-12",
		AgentVersion:      "v0.9.0",
		Mode:              agentconfig.ModeApplySafe,
		Daemon:            true,
		AppliedRevision:   &applied,
		AttemptedRevision: &attempted,
		Status:            agentconfig.StatusRejected,
		Reason:            agentconfig.ReasonUnsafeChanges,
		Base:              json.RawMessage(`{"api":{"url":"http://x"}}`),
		Effective:         json.RawMessage(`{"api":{"url":"http://x"}}`),
		EffectiveDigest:   "sha256:" + strings.Repeat("a", 64),
	}

	t.Run("204", func(t *testing.T) {
		var gotMethod, gotPath, gotContentType string
		var gotBody map[string]any
		srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			gotMethod, gotPath = r.Method, r.URL.Path
			gotContentType = r.Header.Get("Content-Type")
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Errorf("decode body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		if err := srv.client(true).AgentConfig.Report(context.Background(), instanceID, report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if gotMethod != http.MethodPut || gotPath != "/api/agent/instances/33333333-3333-3333-3333-333333333333/config-report" {
			t.Fatalf("unexpected request %s %s", gotMethod, gotPath)
		}
		if gotContentType != "application/json" {
			t.Fatalf("unexpected content type %q", gotContentType)
		}
		for _, key := range []string{"effective-digest", "applied-revision", "attempted-revision", "agent-version"} {
			if _, ok := gotBody[key]; !ok {
				t.Fatalf("report body missing kebab-case key %q: %v", key, gotBody)
			}
		}
		if gotBody["applied-revision"] != float64(6) || gotBody["status"] != "rejected" {
			t.Fatalf("unexpected report body %v", gotBody)
		}
	})

	t.Run("404", func(t *testing.T) {
		srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		err := srv.client(true).AgentConfig.Report(context.Background(), instanceID, report)
		if !errors.Is(err, ErrRemoteConfigUnsupported) {
			t.Fatalf("expected ErrRemoteConfigUnsupported, got %v", err)
		}
	})

	t.Run("500", func(t *testing.T) {
		srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "internal")
		})
		err := srv.client(true).AgentConfig.Report(context.Background(), instanceID, report)
		var apiErr *APIStatusError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected *APIStatusError, got %T %v", err, err)
		}
		if apiErr.StatusCode != http.StatusInternalServerError || apiErr.Body != "internal" {
			t.Fatalf("unexpected error %+v", apiErr)
		}
		if n := srv.requests.Load(); n != 1 {
			t.Fatalf("expected exactly 1 report request (no retries), got %d", n)
		}
	})
}

func TestHeartbeatConfigFieldsSerialization(t *testing.T) {
	base := types.Heartbeat{
		UUID:      uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		CreatedAt: time.Date(2026, time.April, 7, 12, 0, 0, 0, time.UTC),
	}

	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "config_revision") || strings.Contains(string(raw), "config_digest") {
		t.Fatalf("unset config fields must be omitted: %s", raw)
	}

	rev := int64(0)
	withCfg := base
	withCfg.ConfigRevision = &rev
	withCfg.ConfigDigest = "sha256:" + strings.Repeat("b", 64)
	raw, err = json.Marshal(withCfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"config_revision":0`) {
		t.Fatalf("expected config_revision 0 to be present: %s", raw)
	}
	if !strings.Contains(string(raw), `"config_digest":"sha256:`) {
		t.Fatalf("expected config_digest: %s", raw)
	}
}

func TestDoRequestWithHeadersCannotOverrideAuthorization(t *testing.T) {
	var gotAuth, gotCustom string
	srv := newAgentConfigTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	})
	headers := http.Header{}
	headers.Set("Authorization", "Bearer attacker")
	headers.Set("X-Custom", "yes")

	resp, err := srv.client(true).doRequestWithHeaders(context.Background(), http.MethodGet, "/api/test", nil, headers)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	closeResponseBody(resp, nil)
	if gotAuth != "Bearer token-1" {
		t.Fatalf("Authorization overridden: %q", gotAuth)
	}
	if gotCustom != "yes" {
		t.Fatalf("custom header not sent: %q", gotCustom)
	}
}
