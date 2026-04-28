package slack

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	goslack "github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type fakeAPIClient struct {
	authResponse *goslack.AuthTestResponse
	authErr      error
	teamInfo     *goslack.TeamInfo
	teamInfoErr  error
	botInfo      *goslack.Bot
	botInfoErr   error
}

func (f *fakeAPIClient) SendMessageContext(_ context.Context, _ string, _ ...goslack.MsgOption) (string, string, string, error) {
	return "", "", "", nil
}

func (f *fakeAPIClient) AuthTestContext(_ context.Context) (*goslack.AuthTestResponse, error) {
	if f.authErr != nil {
		return nil, f.authErr
	}
	return f.authResponse, nil
}

func (f *fakeAPIClient) GetTeamInfoContext(_ context.Context) (*goslack.TeamInfo, error) {
	if f.teamInfoErr != nil {
		return nil, f.teamInfoErr
	}
	return f.teamInfo, nil
}

func (f *fakeAPIClient) GetBotInfoContext(_ context.Context, _ goslack.GetBotInfoParameters) (*goslack.Bot, error) {
	if f.botInfoErr != nil {
		return nil, f.botInfoErr
	}
	return f.botInfo, nil
}

func TestNewService_WithToken_InitializesClient(t *testing.T) {
	service, err := NewService(&config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
	}, zap.NewNop().Sugar())

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.NotNil(t, service.client)
}

func TestNewService_WithoutToken_DoesNotInitializeClient(t *testing.T) {
	service, err := NewService(&config.SlackConfig{
		Enabled: true,
		Token:   "",
	}, zap.NewNop().Sugar())

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Nil(t, service.client)
}

func TestGetConfigurationUsesAuthTestTeamAndBotInfo(t *testing.T) {
	service := &Service{
		config: &config.SlackConfig{
			Enabled: true,
			Token:   "xoxb-test-token",
		},
		logger: zap.NewNop().Sugar(),
		client: &fakeAPIClient{
			authResponse: &goslack.AuthTestResponse{
				URL:          "https://acme.slack.com/",
				Team:         "Acme",
				TeamID:       "T123",
				BotID:        "B123",
				EnterpriseID: "E123",
			},
			teamInfo: &goslack.TeamInfo{
				ID:          "T123",
				Name:        "Acme Security",
				Domain:      "acme",
				EmailDomain: "acme.example.com",
			},
			botInfo: &goslack.Bot{
				ID:   "B123",
				Name: "Compliance Bot",
			},
		},
	}

	configuration, err := service.GetConfiguration(context.Background())
	require.NoError(t, err)
	assert.Equal(t, WorkspaceConfiguration{
		WorkspaceName:   "Acme Security",
		WorkspaceURL:    "https://acme.slack.com/",
		WorkspaceDomain: "acme",
		EmailDomain:     "acme.example.com",
		TeamID:          "T123",
		BotID:           "B123",
		BotName:         "Compliance Bot",
		EnterpriseID:    "E123",
	}, configuration)
}

func TestGetConfigurationReturnsPartialMetadataWhenTeamOrBotLookupsFail(t *testing.T) {
	service := &Service{
		config: &config.SlackConfig{
			Enabled: true,
			Token:   "xoxb-test-token",
		},
		logger: zap.NewNop().Sugar(),
		client: &fakeAPIClient{
			authResponse: &goslack.AuthTestResponse{
				URL:    "https://acme.slack.com/",
				Team:   "Acme",
				TeamID: "T123",
				BotID:  "B123",
			},
			teamInfoErr: errors.New("team info failed"),
			botInfoErr:  errors.New("bot info failed"),
		},
	}

	configuration, err := service.GetConfiguration(context.Background())
	require.NoError(t, err)
	assert.Equal(t, WorkspaceConfiguration{
		WorkspaceName: "Acme",
		WorkspaceURL:  "https://acme.slack.com/",
		TeamID:        "T123",
		BotID:         "B123",
	}, configuration)
}

func TestGetConfigurationForTokenRequiresToken(t *testing.T) {
	service := &Service{
		config: &config.SlackConfig{Enabled: true},
		logger: zap.NewNop().Sugar(),
		client: &fakeAPIClient{},
	}

	configuration, err := service.GetConfigurationForToken(context.Background(), " ")
	require.Error(t, err)
	assert.Equal(t, WorkspaceConfiguration{}, configuration)
}

func TestGetConfigurationForTokenRequiresConfiguredService(t *testing.T) {
	tests := []struct {
		name    string
		service *Service
	}{
		{
			name:    "nil service",
			service: nil,
		},
		{
			name:    "nil config",
			service: &Service{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configuration, err := tt.service.GetConfigurationForToken(context.Background(), "xoxb-test-token")
			require.Error(t, err)
			assert.Equal(t, "slack service is not configured", err.Error())
			assert.Equal(t, WorkspaceConfiguration{}, configuration)
		})
	}
}

func TestClientForTokenCachesConfiguredClientConcurrently(t *testing.T) {
	service := &Service{
		config: &config.SlackConfig{
			Enabled: true,
			Token:   "xoxb-test-token",
		},
		logger: zap.NewNop().Sugar(),
	}

	const workers = 20
	start := make(chan struct{})
	clients := make(chan apiClient, workers)
	var wg sync.WaitGroup
	wg.Add(workers)

	for range workers {
		go func() {
			defer wg.Done()
			<-start
			clients <- service.clientForToken("xoxb-test-token")
		}()
	}

	close(start)
	wg.Wait()
	close(clients)

	require.NotNil(t, service.client)
	cached := service.client
	for client := range clients {
		assert.True(t, client == cached)
	}
}

func TestSendMessageUsesExistingClientInterface(t *testing.T) {
	service := &Service{
		config: &config.SlackConfig{
			Enabled: true,
			Token:   "xoxb-test-token",
		},
		logger: zap.NewNop().Sugar(),
		client: &fakeAPIClient{},
	}

	result, err := service.SendMessage(context.Background(), "C123", &slacktypes.Message{Text: "hello"})
	require.NoError(t, err)
	assert.True(t, result.Success)
}
