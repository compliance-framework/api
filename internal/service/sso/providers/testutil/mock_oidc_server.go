package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// MockOIDCServer provides a minimal OIDC issuer suitable for unit tests.
type MockOIDCServer struct {
	Server     *httptest.Server
	IssuerURL  string
	privateKey *rsa.PrivateKey
	keyID      string

	userInfo map[string]any

	mu             sync.Mutex
	codeChallenges map[string]string
	tokenRequests  []TokenRequest
}

// TokenRequest is a request received by the mock token endpoint.
type TokenRequest struct {
	Form   url.Values
	Header http.Header
}

// NewMockOIDCServer starts a mock OIDC issuer that serves discovery + JWKS.
func NewMockOIDCServer(t *testing.T) *MockOIDCServer {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mock := &MockOIDCServer{
		privateKey:     privKey,
		keyID:          "test-key",
		codeChallenges: map[string]string{},
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

	mux.HandleFunc("/token", mock.handleToken)

	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known") || r.URL.Path == "/keys" || r.URL.Path == "/userinfo" || r.URL.Path == "/token" {
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

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
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

// IssueCode registers an authorization code the token endpoint will redeem, bound to the PKCE
// S256 code_challenge sent on the authorization request (as an IdP does). Redeeming the code
// requires the code_verifier whose S256 hash matches the challenge.
func (m *MockOIDCServer) IssueCode(code string, codeChallenge string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codeChallenges[code] = codeChallenge
}

// TokenRequests returns the requests received by the token endpoint.
func (m *MockOIDCServer) TokenRequests() []TokenRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]TokenRequest(nil), m.tokenRequests...)
}

// handleToken implements the authorization-code grant with PKCE (RFC 7636 §4.6): the code must
// have been issued with IssueCode, and the code_verifier must hash to its code_challenge.
func (m *MockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	m.tokenRequests = append(m.tokenRequests, TokenRequest{Form: r.PostForm, Header: r.Header.Clone()})
	challenge, ok := m.codeChallenges[r.PostForm.Get("code")]
	m.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || r.PostForm.Get("code_verifier") == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	clientID := r.PostForm.Get("client_id")
	if user, _, hasBasic := r.BasicAuth(); hasBasic {
		clientID = user
	}
	idToken, err := m.SignIDToken(map[string]any{"aud": clientID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access-token",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}
