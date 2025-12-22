package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Service struct {
	config           *config.OIDCConfig
	logger           *zap.SugaredLogger
	providers        map[string]*oidc.Provider
	oauth2Configs    map[string]*oauth2.Config
	verifiers        map[string]*oidc.IDTokenVerifier
	providerTypes    map[string]string
	providerConfigs  map[string]config.OIDCProviderConfig
	supportedOAuthID map[string]struct{}
}

func (s *Service) fetchGitHubOrganizations(client *http.Client, orgsURL string) ([]githubOrg, error) {
	sets := make(map[string]githubOrg)

	if orgsURL != "" {
		if orgs, err := s.fetchGitHubOrgList(client, orgsURL); err == nil {
			for _, org := range orgs {
				name := strings.ToLower(org.Login)
				if name == "" {
					continue
				}
				sets[name] = org
			}
		} else {
			return nil, err
		}
	}

	memberships, err := s.fetchGitHubOrgMemberships(client)
	if err != nil {
		return nil, err
	}
	for _, org := range memberships {
		name := strings.ToLower(org.Login)
		if name == "" {
			continue
		}
		sets[name] = org
	}

	if len(sets) == 0 {
		return nil, nil
	}

	orgs := make([]githubOrg, 0, len(sets))
	for _, org := range sets {
		orgs = append(orgs, org)
	}

	return orgs, nil
}

func (s *Service) fetchGitHubTeams(client *http.Client) ([]githubTeam, error) {
	resp, err := client.Get("https://api.github.com/user/teams")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch GitHub teams: %s", body)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var teams []githubTeam
	if err := json.Unmarshal(data, &teams); err != nil {
		return nil, err
	}

	return teams, nil
}

func (s *Service) fetchGitHubOrgList(client *http.Client, orgsURL string) ([]githubOrg, error) {
	resp, err := client.Get(orgsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch GitHub organizations: %s", body)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var orgs []githubOrg
	if err := json.Unmarshal(data, &orgs); err != nil {
		return nil, err
	}

	return orgs, nil
}

func (s *Service) fetchGitHubOrgMemberships(client *http.Client) ([]githubOrg, error) {
	resp, err := client.Get("https://api.github.com/user/memberships/orgs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch GitHub memberships: %s", body)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var memberships []githubOrgMembership
	if err := json.Unmarshal(data, &memberships); err != nil {
		return nil, err
	}

	var orgs []githubOrg
	for _, membership := range memberships {
		if membership.State != "active" {
			continue
		}
		orgs = append(orgs, membership.Organization)
	}

	return orgs, nil
}

type UserInfo struct {
	Subject      string                 `json:"sub"`
	Email        string                 `json:"email"`
	Name         string                 `json:"name"`
	FirstName    string                 `json:"given_name"`
	LastName     string                 `json:"family_name"`
	Groups       []string               `json:"groups"`
	HostedDomain string                 `json:"hd"`
	Claims       map[string]interface{} `json:"-"`
}

func NewService(cfg *config.OIDCConfig, logger *zap.SugaredLogger) (*Service, error) {
	service := &Service{
		config:           cfg,
		logger:           logger,
		providers:        make(map[string]*oidc.Provider),
		oauth2Configs:    make(map[string]*oauth2.Config),
		verifiers:        make(map[string]*oidc.IDTokenVerifier),
		providerTypes:    make(map[string]string),
		providerConfigs:  make(map[string]config.OIDCProviderConfig),
		supportedOAuthID: map[string]struct{}{"github": {}},
	}

	if cfg == nil || !cfg.Enabled {
		logger.Info("OIDC is disabled")
		return service, nil
	}

	for _, providerConfig := range cfg.Providers {
		if providerConfig.Enabled {
			service.providerConfigs[providerConfig.Name] = providerConfig
			err := service.initializeProvider(providerConfig)
			if err != nil {
				logger.Errorw("Failed to initialize OIDC provider", "provider", providerConfig.Name, "error", err)
				continue
			}
			logger.Infow("Initialized OIDC provider", "provider", providerConfig.Name)
		}
	}

	return service, nil
}

func (s *Service) initializeProvider(providerConfig config.OIDCProviderConfig) error {
	providerType := providerConfig.Type
	if providerType == "" {
		providerType = "oidc"
	}

	switch providerType {
	case "oidc":
		return s.initializeOIDCProvider(providerConfig)
	case "oauth":
		return s.initializeOAuthProvider(providerConfig)
	default:
		return fmt.Errorf("unsupported provider type %s for %s", providerType, providerConfig.Name)
	}
}

func (s *Service) initializeOIDCProvider(providerConfig config.OIDCProviderConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, providerConfig.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to create provider %s: %w", providerConfig.Name, err)
	}

	scopes := providerConfig.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     providerConfig.ClientID,
		ClientSecret: providerConfig.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/%s", s.config.CallbackURL, providerConfig.Name),
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: providerConfig.ClientID})

	s.providers[providerConfig.Name] = provider
	s.oauth2Configs[providerConfig.Name] = oauth2Config
	s.verifiers[providerConfig.Name] = verifier
	s.providerTypes[providerConfig.Name] = "oidc"

	return nil
}

func (s *Service) initializeOAuthProvider(providerConfig config.OIDCProviderConfig) error {
	if _, supported := s.supportedOAuthID[strings.ToLower(providerConfig.Name)]; !supported {
		return fmt.Errorf("oauth provider %s not supported", providerConfig.Name)
	}

	if providerConfig.AuthURL == "" || providerConfig.TokenURL == "" || providerConfig.UserInfoURL == "" {
		return fmt.Errorf("oauth provider %s missing required URLs", providerConfig.Name)
	}

	scopes := providerConfig.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:user", "user:email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     providerConfig.ClientID,
		ClientSecret: providerConfig.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/%s", s.config.CallbackURL, providerConfig.Name),
		Endpoint: oauth2.Endpoint{
			AuthURL:  providerConfig.AuthURL,
			TokenURL: providerConfig.TokenURL,
		},
		Scopes: scopes,
	}

	s.oauth2Configs[providerConfig.Name] = oauth2Config
	s.providerTypes[providerConfig.Name] = "oauth"

	return nil
}

func (s *Service) IsEnabled() bool {
	return s.config != nil && s.config.Enabled
}

func (s *Service) GetEnabledProviders() []config.OIDCProviderConfig {
	if s.config == nil {
		return nil
	}
	return s.config.GetEnabledProviders()
}

func (s *Service) GetOAuth2Config(providerName string) (*oauth2.Config, bool) {
	cfg, exists := s.oauth2Configs[providerName]
	return cfg, exists
}

func (s *Service) GetProvider(providerName string) (*oidc.Provider, bool) {
	p, exists := s.providers[providerName]
	return p, exists
}

func (s *Service) GetProviderConfig(providerName string) *config.OIDCProviderConfig {
	if s.config == nil {
		return nil
	}
	return s.config.GetProvider(providerName)
}

func (s *Service) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *Service) GetAuthURL(providerName, state string) (string, error) {
	oauth2Config, exists := s.oauth2Configs[providerName]
	if !exists {
		return "", fmt.Errorf("provider %s not found", providerName)
	}

	return oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (s *Service) ExchangeCode(ctx context.Context, providerName, code string) (*oauth2.Token, error) {
	oauth2Config, exists := s.oauth2Configs[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return token, nil
}

func (s *Service) GetUserInfo(ctx context.Context, providerName string, token *oauth2.Token) (*UserInfo, error) {
	cfg, ok := s.providerConfigs[providerName]
	if !ok {
		return nil, fmt.Errorf("provider %s not configured", providerName)
	}

	var (
		userInfo *UserInfo
		err      error
	)

	switch s.providerTypes[providerName] {
	case "oauth":
		userInfo, err = s.getOAuthUserInfo(ctx, cfg, token)
	default:
		userInfo, err = s.getOIDCUserInfo(ctx, providerName, token)
	}

	if err != nil {
		return nil, err
	}

	s.augmentUserGroups(cfg, userInfo)

	return userInfo, nil
}

func (s *Service) getOIDCUserInfo(ctx context.Context, providerName string, token *oauth2.Token) (*UserInfo, error) {
	provider, exists := s.providers[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	verifier, exists := s.verifiers[providerName]
	if !exists {
		return nil, fmt.Errorf("verifier for provider %s not found", providerName)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	userInfo := &UserInfo{
		Claims: sanitizeClaims(cloneClaims(claims)),
	}

	if sub, ok := claims["sub"].(string); ok {
		userInfo.Subject = sub
	}
	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		userInfo.FirstName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		userInfo.LastName = familyName
	}

	if groups, ok := claims["groups"].([]interface{}); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				userInfo.Groups = append(userInfo.Groups, gs)
			}
		}
	}
	if hd, ok := claims["hd"].(string); ok {
		userInfo.HostedDomain = hd
	}

	if userInfo.FirstName == "" && userInfo.LastName == "" && userInfo.Name != "" {
		userInfo.FirstName = userInfo.Name
	}

	oauth2Config := s.oauth2Configs[providerName]
	userInfoFromEndpoint, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err == nil {
		var extraClaims map[string]interface{}
		if err := userInfoFromEndpoint.Claims(&extraClaims); err == nil {
			userInfo.Claims = sanitizeClaims(mergeClaims(userInfo.Claims, extraClaims))
			if userInfo.Email == "" {
				if email, ok := extraClaims["email"].(string); ok {
					userInfo.Email = email
				}
			}
			if userInfo.FirstName == "" {
				if givenName, ok := extraClaims["given_name"].(string); ok {
					userInfo.FirstName = givenName
				}
			}
			if userInfo.LastName == "" {
				if familyName, ok := extraClaims["family_name"].(string); ok {
					userInfo.LastName = familyName
				}
			}
		}
	}
	_ = oauth2Config

	if userInfo.HostedDomain == "" {
		userInfo.HostedDomain = extractDomain(userInfo.Email)
	}

	return userInfo, nil
}

func (s *Service) getOAuthUserInfo(ctx context.Context, providerConfig config.OIDCProviderConfig, token *oauth2.Token) (*UserInfo, error) {
	switch strings.ToLower(providerConfig.Name) {
	case "github":
		return s.getGitHubUserInfo(ctx, providerConfig, token)
	default:
		return nil, fmt.Errorf("oauth provider %s not supported", providerConfig.Name)
	}
}

type githubUser struct {
	ID            int64  `json:"id"`
	Login         string `json:"login"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	AvatarURL     string `json:"avatar_url"`
	Company       string `json:"company"`
	Organization  string `json:"organization"`
	Organizations string `json:"organizations_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type githubOrg struct {
	Login string `json:"login"`
}

type githubOrgMembership struct {
	State        string    `json:"state"`
	Role         string    `json:"role"`
	Organization githubOrg `json:"organization"`
}

type githubTeam struct {
	Name         string    `json:"name"`
	Slug         string    `json:"slug"`
	Organization githubOrg `json:"organization"`
}

func (s *Service) getGitHubUserInfo(ctx context.Context, providerConfig config.OIDCProviderConfig, token *oauth2.Token) (*UserInfo, error) {
	oauth2Config, ok := s.oauth2Configs[providerConfig.Name]
	if !ok {
		return nil, fmt.Errorf("oauth config for %s not found", providerConfig.Name)
	}

	client := oauth2Config.Client(ctx, token)

	userResp, err := client.Get(providerConfig.UserInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub user info: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode >= 400 {
		body, _ := io.ReadAll(userResp.Body)
		return nil, fmt.Errorf("GitHub user info request failed: %s", body)
	}

	body, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GitHub user info response: %w", err)
	}

	var rawClaims map[string]interface{}
	if err := json.Unmarshal(body, &rawClaims); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub user info claims: %w", err)
	}

	var ghUser githubUser
	if err := json.Unmarshal(body, &ghUser); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub user info: %w", err)
	}

	userInfo := &UserInfo{
		Subject: fmt.Sprintf("github-%d", ghUser.ID),
		Email:   ghUser.Email,
		Name:    ghUser.Name,
		Claims:  sanitizeClaims(rawClaims),
	}

	if ghUser.Name == "" {
		userInfo.Name = ghUser.Login
	}

	names := strings.Fields(userInfo.Name)
	if len(names) > 0 {
		userInfo.FirstName = names[0]
	}
	if len(names) > 1 {
		userInfo.LastName = strings.Join(names[1:], " ")
	}
	if userInfo.Email == "" && providerConfig.EmailURL != "" {
		email, err := s.fetchGitHubPrimaryEmail(client, providerConfig.EmailURL)
		if err == nil && email != "" {
			userInfo.Email = email
		}
	}

	if userInfo.Email == "" {
		return nil, fmt.Errorf("GitHub user does not have email available")
	}

	if userInfo.Claims == nil {
		userInfo.Claims = make(map[string]interface{})
	}
	userInfo.Claims["sub"] = userInfo.Subject
	userInfo.Claims["email"] = userInfo.Email
	userInfo.Claims["login"] = ghUser.Login
	userInfo.Claims["name"] = userInfo.Name

	orgs, err := s.fetchGitHubOrganizations(client, ghUser.Organizations)
	if err == nil {
		var orgNames []string
		for _, org := range orgs {
			name := strings.ToLower(org.Login)
			if name == "" {
				continue
			}
			userInfo.Groups = append(userInfo.Groups, fmt.Sprintf("github-organization:%s", name))
			orgNames = append(orgNames, name)
		}
		if len(orgNames) > 0 {
			userInfo.Claims["organizations"] = orgNames
		}
	}

	teams, err := s.fetchGitHubTeams(client)
	if err == nil {
		var teamEntries []string
		for _, team := range teams {
			orgName := strings.ToLower(team.Organization.Login)
			teamSlug := strings.ToLower(team.Slug)
			if orgName == "" || teamSlug == "" {
				continue
			}
			entry := fmt.Sprintf("%s:%s", orgName, teamSlug)
			userInfo.Groups = append(userInfo.Groups, fmt.Sprintf("team:%s", entry))
			teamEntries = append(teamEntries, entry)
		}
		if len(teamEntries) > 0 {
			userInfo.Claims["team"] = teamEntries
		}
	}

	userInfo.HostedDomain = extractDomain(userInfo.Email)

	return userInfo, nil
}

func (s *Service) fetchGitHubPrimaryEmail(client *http.Client, emailURL string) (string, error) {
	resp, err := client.Get(emailURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to fetch GitHub emails: %s", body)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []githubEmail
	if err := json.Unmarshal(data, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", nil
}

func (s *Service) CanCreateUser(userInfo *UserInfo, providerConfig *config.OIDCProviderConfig) bool {
	if providerConfig == nil {
		return false
	}

	if len(providerConfig.GroupMapping) == 0 {
		return true
	}

	userGroups := make(map[string]bool)
	for _, group := range userInfo.Groups {
		userGroups[strings.ToLower(group)] = true
	}

	for requiredGroup := range providerConfig.GroupMapping {
		if userGroups[strings.ToLower(requiredGroup)] {
			return true
		}
	}

	return false
}

func (s *Service) MapUserAttributes(userInfo *UserInfo, providerConfig *config.OIDCProviderConfig) []string {
	if providerConfig == nil || len(providerConfig.GroupMapping) == 0 {
		return nil
	}

	userGroups := make(map[string]bool)
	for _, group := range userInfo.Groups {
		userGroups[strings.ToLower(group)] = true
	}

	attributeSet := make(map[string]bool)
	for oidcGroup, attributes := range providerConfig.GroupMapping {
		if userGroups[strings.ToLower(oidcGroup)] {
			for _, attr := range attributes {
				attributeSet[attr] = true
			}
		}
	}

	var result []string
	for attr := range attributeSet {
		result = append(result, attr)
	}

	return result
}

func SerializeStringArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	data, _ := json.Marshal(arr)
	return string(data)
}

func DeserializeStringArray(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var arr []string
	json.Unmarshal([]byte(s), &arr)
	return arr
}

func (s *Service) augmentUserGroups(providerConfig config.OIDCProviderConfig, userInfo *UserInfo) {
	if userInfo == nil {
		return
	}

	normalized := make(map[string]struct{})
	deduped := make([]string, 0, len(userInfo.Groups))
	addGroup := func(group string) {
		group = strings.TrimSpace(group)
		if group == "" {
			return
		}
		key := strings.ToLower(group)
		if _, exists := normalized[key]; exists {
			return
		}
		normalized[key] = struct{}{}
		deduped = append(deduped, group)
	}

	for _, g := range userInfo.Groups {
		addGroup(g)
	}

	for _, g := range buildClaimGroups(userInfo.Claims) {
		addGroup(g)
	}

	domain := strings.ToLower(strings.TrimSpace(userInfo.HostedDomain))
	if domain == "" {
		domain = extractDomain(userInfo.Email)
	}
	if domain != "" {
		addGroup(fmt.Sprintf("domain:%s", domain))
	}

	for source, targets := range providerConfig.GroupMapping {
		sourceKey := strings.ToLower(strings.TrimSpace(source))
		if sourceKey == "" {
			continue
		}

		matched := false
		if _, exists := normalized[sourceKey]; exists {
			matched = true
		} else if strings.HasPrefix(sourceKey, "domain:") && domain != "" {
			expected := strings.TrimSpace(strings.TrimPrefix(sourceKey, "domain:"))
			if expected == domain {
				matched = true
				addGroup(fmt.Sprintf("domain:%s", domain))
				normalized[sourceKey] = struct{}{}
			}
		}

		if !matched {
			continue
		}

		for _, target := range targets {
			addGroup(target)
		}
	}

	userInfo.Groups = deduped
}

func extractDomain(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at == -1 || at == len(email)-1 {
		return ""
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	return domain
}

func cloneClaims(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return make(map[string]interface{})
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func mergeClaims(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = make(map[string]interface{})
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func sanitizeClaims(claims map[string]interface{}) map[string]interface{} {
	if claims == nil {
		return nil
	}

	disallowedKeys := map[string]struct{}{
		"avatar_url":          {},
		"bio":                 {},
		"blog":                {},
		"company":             {},
		"email_verified":      {},
		"followers":           {},
		"followers_url":       {},
		"following":           {},
		"following_url":       {},
		"gists_url":           {},
		"gravatar_id":         {},
		"hireable":            {},
		"html_url":            {},
		"location":            {},
		"node_id":             {},
		"organizations_url":   {},
		"public_gists":        {},
		"public_repos":        {},
		"received_events_url": {},
		"repos_url":           {},
		"site_admin":          {},
		"starred_url":         {},
		"subscriptions_url":   {},
		"type":                {},
		"url":                 {},
	}

	for key := range claims {
		if _, blocked := disallowedKeys[strings.ToLower(key)]; blocked {
			delete(claims, key)
		}
	}

	return claims
}

func buildClaimGroups(claims map[string]interface{}) []string {
	if len(claims) == 0 {
		return nil
	}

	var groups []string
	for key, value := range claims {
		key = strings.TrimSpace(strings.ToLower(key))
		if key == "" {
			continue
		}

		values := claimValueToStrings(value)
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			groups = append(groups, fmt.Sprintf("%s:%s", key, v))
		}
	}

	return groups
}

func claimValueToStrings(value interface{}) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case bool:
		return []string{strconv.FormatBool(v)}
	case int:
		return []string{strconv.Itoa(v)}
	case int64:
		return []string{strconv.FormatInt(v, 10)}
	case float64:
		return []string{strconv.FormatFloat(v, 'f', -1, 64)}
	case json.Number:
		return []string{v.String()}
	case []interface{}:
		var combined []string
		for _, item := range v {
			combined = append(combined, claimValueToStrings(item)...)
		}
		return combined
	case map[string]interface{}:
		if data, err := json.Marshal(v); err == nil {
			return []string{string(data)}
		}
	}

	return []string{fmt.Sprint(value)}
}
