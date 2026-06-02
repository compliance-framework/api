package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type stubProviderCatalog struct {
	providers []notification.ProviderMetadata
}

func (s stubProviderCatalog) Provider(providerID string) (notification.Provider, bool) {
	return nil, false
}

func (s stubProviderCatalog) ProviderIDs() []string {
	providerIDs := make([]string, 0, len(s.providers))
	for _, provider := range s.providers {
		providerIDs = append(providerIDs, provider.ProviderType)
	}
	return providerIDs
}

func (s stubProviderCatalog) Providers() []notification.ProviderMetadata {
	return append([]notification.ProviderMetadata(nil), s.providers...)
}

type stubNotificationTestEnqueuer struct {
	started bool
	jobIDs  []int64
}

func (s *stubNotificationTestEnqueuer) IsStarted() bool {
	return s.started
}

func (s *stubNotificationTestEnqueuer) EnqueueNotificationEmail(_ context.Context, _ emailprovider.Delivery) ([]int64, error) {
	return append([]int64(nil), s.jobIDs...), nil
}

func (s *stubNotificationTestEnqueuer) EnqueueNotificationSlack(_ context.Context, _ slackprovider.Delivery) ([]int64, error) {
	return append([]int64(nil), s.jobIDs...), nil
}

func TestSendTestNotificationReturnsJobIDs(t *testing.T) {
	e := echo.New()
	e.Validator = middleware.NewValidator()

	handler := &NotificationsHandler{
		sugar:     zap.NewNop().Sugar(),
		cfg:       &config.Config{},
		providers: notificationproviders.NewLookup(),
		enqueuer: &stubNotificationTestEnqueuer{
			started: true,
			jobIDs:  []int64{42},
		},
	}

	payload := []byte(`{"providerType":"email","destinationTarget":"alerts@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/notifications/test", bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	err := handler.SendTestNotification(e.NewContext(req, rec))
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, rec.Code)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	data, ok := raw["data"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, data, "correlationId")
	require.Equal(t, []any{float64(42)}, data["jobIds"])

	var response GenericDataResponse[testNotificationResponse]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Equal(t, []int64{42}, response.Data.JobIDs)
	require.Equal(t, notification.DeliveryChannelEmail, response.Data.ProviderType)
}

func TestListNotificationProvidersReturnsProviderErrors(t *testing.T) {
	e := echo.New()
	handler := &NotificationsHandler{
		sugar: zap.NewNop().Sugar(),
		providers: stubProviderCatalog{providers: []notification.ProviderMetadata{
			{
				ProviderType: notification.DeliveryChannelSlack,
				DisplayName:  "Slack",
				Description:  "Configured Slack workspace",
				Enabled:      true,
				Error:        "invalid_auth",
			},
		}},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/notifications/providers", nil)
	rec := httptest.NewRecorder()

	err := handler.ListNotificationProviders(e.NewContext(req, rec))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	var response GenericDataListResponse[availableNotificationProviderResponse]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Len(t, response.Data, 1)
	require.Equal(t, availableNotificationProviderResponse{
		ProviderType: notification.DeliveryChannelSlack,
		DisplayName:  "Slack",
		Description:  "Configured Slack workspace",
		Enabled:      true,
		Error:        "invalid_auth",
	}, response.Data[0])
}
