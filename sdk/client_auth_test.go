package sdk

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
)

func newAuthenticatedTestClient(handler roundTripFunc) *Client {
	return NewClient(&http.Client{Transport: handler}, &Config{
		BaseURL: "http://example.test",
		AgentAuth: &AgentAuthConfig{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
	})
}

func TestClientAgentAuthUsesTokenEndpointWithBasicAuth(t *testing.T) {
	var (
		mu                     sync.Mutex
		tokenMethod            string
		tokenPath              string
		tokenAuthorization     string
		protectedAuthorization string
	)

	client := newAuthenticatedTestClient(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()

		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenMethod = r.Method
			tokenPath = r.URL.Path
			tokenAuthorization = r.Header.Get("Authorization")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"token-1","token_type":"bearer","expires_in":3600}`)),
				Header:     make(http.Header),
			}, nil
		case "/api/test":
			protectedAuthorization = r.Header.Get("Authorization")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	resp, err := client.NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	closeResponseBody(resp, nil)

	if tokenMethod != http.MethodPost {
		t.Fatalf("expected token method %q, got %q", http.MethodPost, tokenMethod)
	}
	if tokenPath != "/api/auth/agent/token" {
		t.Fatalf("expected token path %q, got %q", "/api/auth/agent/token", tokenPath)
	}

	expectedBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-id:client-secret"))
	if tokenAuthorization != expectedBasic {
		t.Fatalf("expected basic auth %q, got %q", expectedBasic, tokenAuthorization)
	}
	if protectedAuthorization != "Bearer token-1" {
		t.Fatalf("expected protected request auth %q, got %q", "Bearer token-1", protectedAuthorization)
	}
}

func TestClientNewRequestLeavesRequestUnauthenticatedWithoutAgentAuth(t *testing.T) {
	var authHeader string

	client := NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		authHeader = r.Header.Get("Authorization")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}, &Config{BaseURL: "http://example.test"})

	resp, err := client.NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	closeResponseBody(resp, nil)

	if authHeader != "" {
		t.Fatalf("expected no authorization header, got %q", authHeader)
	}
}

func TestClientReusesCachedAgentTokenUntilNearExpiry(t *testing.T) {
	var (
		tokenCalls     int
		protectedCalls int
	)

	client := newAuthenticatedTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"cached-token","token_type":"bearer","expires_in":3600}`)),
				Header:     make(http.Header),
			}, nil
		case "/api/test":
			protectedCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	for range 2 {
		resp, err := client.NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		closeResponseBody(resp, nil)
	}

	if tokenCalls != 1 {
		t.Fatalf("expected one token request, got %d", tokenCalls)
	}
	if protectedCalls != 2 {
		t.Fatalf("expected two protected requests, got %d", protectedCalls)
	}
}

func TestClientTreatsNearlyExpiredTokenAsStale(t *testing.T) {
	var tokenCalls int

	client := newAuthenticatedTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"short-lived","token_type":"bearer","expires_in":30}`)),
				Header:     make(http.Header),
			}, nil
		case "/api/test":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	for range 2 {
		resp, err := client.NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		closeResponseBody(resp, nil)
	}

	if tokenCalls != 2 {
		t.Fatalf("expected near-expiry token to be refreshed, got %d token requests", tokenCalls)
	}
}

func TestClientRetriesOnceOnProtectedCall401(t *testing.T) {
	var (
		tokenCalls           int
		protectedAuthHeaders []string
	)

	client := newAuthenticatedTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenCalls++
			token := "token-1"
			if tokenCalls == 2 {
				token = "token-2"
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"` + token + `","token_type":"bearer","expires_in":3600}`)),
				Header:     make(http.Header),
			}, nil
		case "/api/test":
			protectedAuthHeaders = append(protectedAuthHeaders, r.Header.Get("Authorization"))
			status := http.StatusUnauthorized
			if len(protectedAuthHeaders) == 2 {
				status = http.StatusOK
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	resp, err := client.NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	closeResponseBody(resp, nil)

	if tokenCalls != 2 {
		t.Fatalf("expected two token requests, got %d", tokenCalls)
	}
	if len(protectedAuthHeaders) != 2 {
		t.Fatalf("expected two protected requests, got %d", len(protectedAuthHeaders))
	}
	if protectedAuthHeaders[0] != "Bearer token-1" || protectedAuthHeaders[1] != "Bearer token-2" {
		t.Fatalf("unexpected protected auth headers: %#v", protectedAuthHeaders)
	}
}

func TestClientDoesNotRetryOnProtectedCall403(t *testing.T) {
	var (
		tokenCalls     int
		protectedCalls int
	)

	client := newAuthenticatedTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"token-1","token_type":"bearer","expires_in":3600}`)),
				Header:     make(http.Header),
			}, nil
		case "/api/test":
			protectedCalls++
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	resp, err := client.NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	closeResponseBody(resp, nil)

	if tokenCalls != 1 {
		t.Fatalf("expected one token request, got %d", tokenCalls)
	}
	if protectedCalls != 1 {
		t.Fatalf("expected one protected request, got %d", protectedCalls)
	}
}

func TestClientDoesNotLoopOnSecond401(t *testing.T) {
	var (
		tokenCalls     int
		protectedCalls int
	)

	client := newAuthenticatedTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/auth/agent/token":
			tokenCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"token","token_type":"bearer","expires_in":3600}`)),
				Header:     make(http.Header),
			}, nil
		case "/api/test":
			protectedCalls++
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})

	resp, err := client.NewRequest(context.Background(), http.MethodPost, "/api/test", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	closeResponseBody(resp, nil)

	if tokenCalls != 2 {
		t.Fatalf("expected two token requests, got %d", tokenCalls)
	}
	if protectedCalls != 2 {
		t.Fatalf("expected two protected requests, got %d", protectedCalls)
	}
}

func TestAuthenticatedSDKMethodsAttachBearerToken(t *testing.T) {
	type call struct {
		name string
		run  func(context.Context, *Client) error
		path string
	}

	cases := []call{
		{
			name: "evidence",
			path: "/api/evidence",
			run: func(ctx context.Context, client *Client) error {
				return client.Evidence.Create(ctx, types.Evidence{
					UUID:  uuid.New(),
					Title: "evidence",
					Start: time.Now().Add(-time.Hour),
					End:   time.Now().Add(-time.Minute),
					Status: types.ObjectiveStatus{
						State: "satisfied",
					},
				})
			},
		},
		{
			name: "risk-template",
			path: "/api/agent/risk-templates/batch",
			run: func(ctx context.Context, client *Client) error {
				return client.RiskTemplate.Upsert(ctx, "plugin-a", "package-a", types.RiskTemplate{
					ID:           uuid.NewString(),
					Name:         "template-a",
					Title:        "Template A",
					Statement:    "Template statement",
					ViolationIds: []string{"violation-a"},
				})
			},
		},
		{
			name: "subject-template",
			path: "/api/agent/subject-templates/batch",
			run: func(ctx context.Context, client *Client) error {
				return client.SubjectTemplate.Upsert(ctx, "plugin-a", types.SubjectTemplate{
					ID:                uuid.NewString(),
					Name:              "template-a",
					Type:              "component",
					IdentityLabelKeys: []string{"asset_id"},
					SourceMode:        "runtime-derived",
					SelectorLabels: []types.SubjectTemplateSelectorLabel{
						{Key: "_plugin", Value: "plugin-a"},
					},
					LabelSchema: []types.SubjectTemplateLabelSchema{
						{Key: "asset_id"},
					},
				})
			},
		},
		{
			name: "heartbeat",
			path: "/api/agent/heartbeat",
			run: func(ctx context.Context, client *Client) error {
				return client.Heartbeat.Create(ctx, types.Heartbeat{
					UUID:      uuid.New(),
					CreatedAt: time.Now().UTC(),
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var authHeader string

			client := newAuthenticatedTestClient(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/api/auth/agent/token":
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"access_token":"token-1","token_type":"bearer","expires_in":3600}`)),
						Header:     make(http.Header),
					}, nil
				case tc.path:
					authHeader = r.Header.Get("Authorization")
					status := http.StatusCreated
					if tc.path != "/api/evidence" && tc.path != "/api/agent/heartbeat" {
						status = http.StatusOK
					}
					return &http.Response{
						StatusCode: status,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				default:
					t.Fatalf("unexpected path %q", r.URL.Path)
					return nil, nil
				}
			})

			if err := tc.run(context.Background(), client); err != nil {
				t.Fatalf("%s call failed: %v", tc.name, err)
			}
			if authHeader != "Bearer token-1" {
				t.Fatalf("expected bearer auth header, got %q", authHeader)
			}
		})
	}
}
