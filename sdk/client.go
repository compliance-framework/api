package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const agentTokenExpirySkew = time.Minute

type AgentAuthConfig struct {
	ClientID     string
	ClientSecret string
}

type Config struct {
	BaseURL string
	Logger  *zap.SugaredLogger

	AgentAuth *AgentAuthConfig
}

type Client struct {
	httpClient *http.Client

	config *Config

	tokenMu              sync.Mutex
	tokenRefreshCh       chan struct{}
	cachedAccessToken    string
	cachedTokenType      string
	cachedTokenExpiresAt time.Time

	Evidence *evidenceClient

	RiskTemplate *riskTemplateClient

	SubjectTemplate *subjectTemplateClient

	Heartbeat *heartbeatClient
}

func NewClient(client *http.Client, config *Config) *Client {
	if client == nil {
		client = http.DefaultClient
	}
	if config == nil {
		config = &Config{}
	}

	c := &Client{
		httpClient: client,
		config:     config,
	}

	c.Evidence = &evidenceClient{client: c}
	c.RiskTemplate = &riskTemplateClient{client: c}
	c.SubjectTemplate = &subjectTemplateClient{client: c}
	c.Heartbeat = &heartbeatClient{client: c}

	return c
}

func (c *Client) NewRequest(ctx context.Context, method string, path string, reader io.Reader) (*http.Response, error) {
	body, err := readRequestBody(reader)
	if err != nil {
		return nil, err
	}

	return c.doRequest(ctx, method, path, body)
}

func (c *Client) doJSONRequest(ctx context.Context, method string, path string, payload any) (*http.Response, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	return c.doRequest(ctx, method, path, body)
}

func (c *Client) doRequest(ctx context.Context, method string, path string, body []byte) (*http.Response, error) {
	if !c.hasAgentAuth() {
		return c.executeRequest(ctx, method, path, body, "")
	}

	tokenType, accessToken, err := c.getAgentAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := c.executeRequest(ctx, method, path, body, formatAuthorizationHeader(tokenType, accessToken))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	closeResponseBody(resp, c.config.Logger)
	c.invalidateAgentAccessToken()

	tokenType, accessToken, err = c.getAgentAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	return c.executeRequest(ctx, method, path, body, formatAuthorizationHeader(tokenType, accessToken))
}

func (c *Client) executeRequest(ctx context.Context, method string, path string, body []byte, authorization string) (*http.Response, error) {
	path = strings.TrimPrefix(path, "/")
	url := strings.TrimSuffix(c.config.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s/%s", url, path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return c.httpClient.Do(req)
}

func (c *Client) hasAgentAuth() bool {
	return c.config != nil &&
		c.config.AgentAuth != nil &&
		strings.TrimSpace(c.config.AgentAuth.ClientID) != "" &&
		strings.TrimSpace(c.config.AgentAuth.ClientSecret) != ""
}

func (c *Client) getAgentAccessToken(ctx context.Context) (string, string, error) {
	for {
		tokenType, accessToken, refreshCh, shouldFetch := c.getAgentAccessTokenState()
		if accessToken != "" {
			return tokenType, accessToken, nil
		}
		if shouldFetch {
			return c.fetchAndCacheAgentAccessToken(ctx, refreshCh)
		}

		select {
		case <-refreshCh:
		case <-ctx.Done():
			return "", "", ctx.Err()
		}
	}
}

func (c *Client) invalidateAgentAccessToken() {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	c.cachedAccessToken = ""
	c.cachedTokenType = ""
	c.cachedTokenExpiresAt = time.Time{}
}

func (c *Client) getAgentAccessTokenState() (string, string, chan struct{}, bool) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.hasFreshAgentAccessTokenLocked() {
		return c.cachedTokenType, c.cachedAccessToken, nil, false
	}
	if c.tokenRefreshCh != nil {
		return "", "", c.tokenRefreshCh, false
	}

	c.tokenRefreshCh = make(chan struct{})
	return "", "", c.tokenRefreshCh, true
}

func (c *Client) hasFreshAgentAccessTokenLocked() bool {
	return c.cachedAccessToken != "" && time.Now().UTC().Add(agentTokenExpirySkew).Before(c.cachedTokenExpiresAt)
}

func (c *Client) fetchAndCacheAgentAccessToken(ctx context.Context, refreshCh chan struct{}) (string, string, error) {
	tokenType, accessToken, expiresAt, err := c.fetchAgentAccessToken(ctx)

	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if err == nil {
		c.cachedAccessToken = accessToken
		c.cachedTokenType = tokenType
		c.cachedTokenExpiresAt = expiresAt
	}
	if c.tokenRefreshCh == refreshCh {
		close(c.tokenRefreshCh)
		c.tokenRefreshCh = nil
	}
	if err != nil {
		return "", "", err
	}

	return c.cachedTokenType, c.cachedAccessToken, nil
}

func (c *Client) fetchAgentAccessToken(ctx context.Context) (string, string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/auth/agent/token", strings.TrimSuffix(c.config.BaseURL, "/")), nil)
	if err != nil {
		return "", "", time.Time{}, err
	}
	req.SetBasicAuth(strings.TrimSpace(c.config.AgentAuth.ClientID), strings.TrimSpace(c.config.AgentAuth.ClientSecret))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer closeResponseBody(resp, c.config.Logger)

	if resp.StatusCode != http.StatusOK {
		return "", "", time.Time{}, fmt.Errorf("agent auth failed with status code: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", "", time.Time{}, err
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", "", time.Time{}, fmt.Errorf("agent auth response missing access_token")
	}

	return tokenResp.TokenType, tokenResp.AccessToken, time.Now().UTC().Add(time.Duration(tokenResp.ExpiresIn) * time.Second), nil
}

func formatAuthorizationHeader(tokenType, accessToken string) string {
	normalizedTokenType := strings.TrimSpace(tokenType)
	if normalizedTokenType == "" {
		normalizedTokenType = "Bearer"
	} else if strings.EqualFold(normalizedTokenType, "bearer") {
		normalizedTokenType = "Bearer"
	}

	return fmt.Sprintf("%s %s", normalizedTokenType, accessToken)
}

func readRequestBody(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, nil
	}

	return io.ReadAll(reader)
}

func closeResponseBody(resp *http.Response, logger *zap.SugaredLogger) {
	if resp == nil || resp.Body == nil {
		return
	}

	if err := resp.Body.Close(); err != nil && logger != nil {
		logger.Errorw("failed to close response body", "err", err)
	}
}
