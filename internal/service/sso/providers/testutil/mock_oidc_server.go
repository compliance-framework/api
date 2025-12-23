package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// MockOIDCServer provides a minimal OIDC issuer suitable for unit tests.
type MockOIDCServer struct {
	Server     *httptest.Server
	IssuerURL  string
	privateKey *rsa.PrivateKey
	keyID      string

	userInfo map[string]any
}

// NewMockOIDCServer starts a mock OIDC issuer that serves discovery + JWKS.
func NewMockOIDCServer(t *testing.T) *MockOIDCServer {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mock := &MockOIDCServer{
		privateKey: privKey,
		keyID:      "test-key",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]any{
			"issuer":                 mock.IssuerURL,
			"jwks_uri":               fmt.Sprintf("%s/keys", mock.IssuerURL),
			"authorization_endpoint": fmt.Sprintf("%s/auth", mock.IssuerURL),
			"token_endpoint":         fmt.Sprintf("%s/token", mock.IssuerURL),
			"userinfo_endpoint":      fmt.Sprintf("%s/userinfo", mock.IssuerURL),
			"end_session_endpoint":   fmt.Sprintf("%s/logout", mock.IssuerURL),
		}
		_ = json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			KeyID: mock.keyID,
			Key:   &mock.privateKey.PublicKey,
			Use:   "sig",
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JSONWebKey{jwk},
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if mock.userInfo == nil {
			mock.userInfo = map[string]any{
				"sub":   "test-subject",
				"email": "test@example.com",
			}
		}
		_ = json.NewEncoder(w).Encode(mock.userInfo)
	})

	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known") || r.URL.Path == "/keys" || r.URL.Path == "/userinfo" {
			mux.ServeHTTP(w, r)
			return
		}
		// Default stub for any other endpoint.
		w.WriteHeader(http.StatusOK)
	}))

	mock.IssuerURL = mock.Server.URL
	return mock
}

// Close shuts down the underlying test server.
func (m *MockOIDCServer) Close() {
	if m.Server != nil {
		m.Server.Close()
	}
}

// SignIDToken signs the provided claims and returns a compact JWT string.
func (m *MockOIDCServer) SignIDToken(claims map[string]any) (string, error) {
	if claims == nil {
		claims = map[string]any{}
	}

	now := time.Now()
	ensureClaim(claims, "iss", m.IssuerURL)
	ensureClaim(claims, "aud", "test-client")
	ensureClaim(claims, "iat", now.Unix())
	ensureClaim(claims, "exp", now.Add(5*time.Minute).Unix())
	ensureClaim(claims, "sub", "test-subject")

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:       m.privateKey,
			KeyID:     m.keyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	raw, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize jwt: %w", err)
	}
	return raw, nil
}

func ensureClaim(claims map[string]any, key string, value any) {
	if _, ok := claims[key]; !ok {
		claims[key] = value
	}
}

// SetUserInfo sets the JSON object returned from /userinfo.
func (m *MockOIDCServer) SetUserInfo(data map[string]any) {
	m.userInfo = data
}
