//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func TestNotificationsApi(t *testing.T) {
	suite.Run(t, new(NotificationsApiIntegrationSuite))
}

type NotificationsApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *NotificationsApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config, &APIServices{})
}

func (suite *NotificationsApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

func (suite *NotificationsApiIntegrationSuite) authedRequest(method string, path string) (*httptest.ResponseRecorder, *http.Request) {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+*token)
	return rec, req
}

func (suite *NotificationsApiIntegrationSuite) authedJSONRequest(method string, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	payload, err := json.Marshal(body)
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+*token)
	req.Header.Set("Content-Type", "application/json")
	return rec, req
}

func (suite *NotificationsApiIntegrationSuite) TestListSystemNotifications() {
	suite.Require().NoError(suite.DB.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				slackprovider.AddressKeyChannel:    "ccf-slack-int",
				slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
			},
		}),
	}).Error)

	suite.Require().NoError(suite.DB.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeEvidenceDigest,
		Provider:         notification.DeliveryChannelEmail,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				emailprovider.AddressKeyEmail: "alerts@example.com",
			},
		}),
	}).Error)

	suite.Require().NoError(suite.DB.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				slackprovider.AddressKeyChannel:    "ccf-slack-int",
				slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
			},
		}),
	}).Error)

	rec, req := suite.authedRequest(http.MethodGet, "/api/admin/notifications")

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListSystemNotifications")

	var response GenericDataListResponse[systemNotificationResponse]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal notifications response")
	suite.Require().Len(response.Data, 1)

	byName := make(map[string]systemNotificationResponse, len(response.Data))
	for _, item := range response.Data {
		byName[item.Name] = item
	}

	digestConfig, ok := byName["EVIDENCE_DIGEST"]
	suite.True(ok, "Expected EVIDENCE_DIGEST entry")
	suite.Len(digestConfig.ConfiguredDestinations, 2)
	suite.Equal([]configuredSystemDestinationResponse{
		{ProviderType: "email", DestinationTarget: "alerts@example.com"},
		{ProviderType: "slack", DestinationTarget: "ccf-slack-int"},
	}, digestConfig.ConfiguredDestinations)
}

func (suite *NotificationsApiIntegrationSuite) TestListSystemNotificationsIncludesConfiguredSupportedTypesOutsideDefaultBaseline() {
	suite.Require().NoError(suite.DB.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeTaskAvailable,
		Provider:         notification.DeliveryChannelEmail,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				emailprovider.AddressKeyEmail: "alerts@example.com",
			},
		}),
	}).Error)

	rec, req := suite.authedRequest(http.MethodGet, "/api/admin/notifications")

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListSystemNotifications")

	var response GenericDataListResponse[systemNotificationResponse]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal notifications response")
	suite.Require().Len(response.Data, 1)

	suite.Equal("TASK_AVAILABLE", response.Data[0].Name)
	suite.Equal([]configuredSystemDestinationResponse{
		{ProviderType: "email", DestinationTarget: "alerts@example.com"},
	}, response.Data[0].ConfiguredDestinations)
}

func (suite *NotificationsApiIntegrationSuite) TestListSystemNotificationsReturnsEmptyDataWhenNoConfigurationsExist() {
	rec, req := suite.authedRequest(http.MethodGet, "/api/admin/notifications")

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListSystemNotifications")

	var response GenericDataListResponse[systemNotificationResponse]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal notifications response")
	suite.Empty(response.Data)
}

func (suite *NotificationsApiIntegrationSuite) TestCreateSystemNotificationDestination() {
	rec, req := suite.authedJSONRequest(http.MethodPost, "/api/admin/notifications/EVIDENCE_DIGEST/destinations", map[string]string{
		"providerType":      "email",
		"destinationTarget": "alerts@example.com",
	})

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code, "Expected Created response for CreateSystemNotificationDestination")

	var response GenericDataResponse[configuredSystemDestinationResponse]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal create notification response")
	suite.Equal(configuredSystemDestinationResponse{
		ProviderType:      "email",
		DestinationTarget: "alerts@example.com",
	}, response.Data)

	var rows []relational.SystemNotificationDestination
	suite.Require().NoError(suite.DB.Find(&rows).Error)
	suite.Require().Len(rows, 1)
	suite.Equal(notification.NotificationTypeEvidenceDigest, rows[0].NotificationType)
	suite.Equal(notification.DeliveryChannelEmail, rows[0].Provider)
	suite.Equal("alerts@example.com", rows[0].Target.Data().Address[emailprovider.AddressKeyEmail])
}

func (suite *NotificationsApiIntegrationSuite) TestCreateSystemNotificationDestinationAcceptsKebabCasePayload() {
	rec, req := suite.authedJSONRequest(http.MethodPost, "/api/admin/notifications/EVIDENCE_DIGEST/destinations", map[string]string{
		"provider-type":      "email",
		"destination-target": "alerts@example.com",
	})

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code, "Expected Created response for kebab-case create payload")

	var response GenericDataResponse[configuredSystemDestinationResponse]
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal create notification response")
	suite.Equal(configuredSystemDestinationResponse{
		ProviderType:      "email",
		DestinationTarget: "alerts@example.com",
	}, response.Data)
}

func (suite *NotificationsApiIntegrationSuite) TestCreateSystemNotificationDestinationSlackDefaultsTargetTypeToChannel() {
	rec, req := suite.authedJSONRequest(http.MethodPost, "/api/admin/notifications/TASK_AVAILABLE/destinations", map[string]string{
		"providerType":      "slack",
		"destinationTarget": "ccf-slack-int",
	})

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code, "Expected Created response for CreateSystemNotificationDestination")

	var rows []relational.SystemNotificationDestination
	suite.Require().NoError(suite.DB.Find(&rows).Error)
	suite.Require().Len(rows, 1)
	suite.Equal(notification.NotificationTypeTaskAvailable, rows[0].NotificationType)
	suite.Equal(notification.DeliveryChannelSlack, rows[0].Provider)
	suite.Equal("ccf-slack-int", rows[0].Target.Data().Address[slackprovider.AddressKeyChannel])
	suite.Equal(slackprovider.TargetTypeChannel, rows[0].Target.Data().Address[slackprovider.AddressKeyTargetType])
}

func (suite *NotificationsApiIntegrationSuite) TestCreateSystemNotificationDestinationRejectsDuplicateDestination() {
	suite.Require().NoError(suite.DB.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeEvidenceDigest,
		Provider:         notification.DeliveryChannelEmail,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				emailprovider.AddressKeyEmail: "alerts@example.com",
			},
		}),
	}).Error)

	rec, req := suite.authedJSONRequest(http.MethodPost, "/api/admin/notifications/EVIDENCE_DIGEST/destinations", map[string]string{
		"providerType":      "email",
		"destinationTarget": "Alerts <alerts@example.com>",
	})

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusConflict, rec.Code, "Expected Conflict response for duplicate notification destination")

	var rows []relational.SystemNotificationDestination
	suite.Require().NoError(suite.DB.Find(&rows).Error)
	suite.Require().Len(rows, 1)
}

func (suite *NotificationsApiIntegrationSuite) TestCreateSystemNotificationDestinationRejectsInvalidInput() {
	rec, req := suite.authedJSONRequest(http.MethodPost, "/api/admin/notifications/not_real/destinations", map[string]string{
		"providerType":      "email",
		"destinationTarget": "alerts@example.com",
	})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code, "Expected BadRequest response for unsupported notification type")

	rec, req = suite.authedJSONRequest(http.MethodPost, "/api/admin/notifications/EVIDENCE_DIGEST/destinations", map[string]string{
		"providerType":      "pagerduty",
		"destinationTarget": "alerts@example.com",
	})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code, "Expected BadRequest response for unsupported provider")

	rec, req = suite.authedJSONRequest(http.MethodPost, "/api/admin/notifications/EVIDENCE_DIGEST/destinations", map[string]string{
		"providerType":      "email",
		"destinationTarget": "not-an-email",
	})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code, "Expected BadRequest response for invalid destination target")
}

func (suite *NotificationsApiIntegrationSuite) TestCreateSystemNotificationDestinationUnauthorized() {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/notifications/EVIDENCE_DIGEST/destinations", bytes.NewReader([]byte(`{"providerType":"email","destinationTarget":"alerts@example.com"}`)))
	req.Header.Set("Content-Type", "application/json")

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnauthorized, rec.Code, "Expected Unauthorized response for missing token")
}

func (suite *NotificationsApiIntegrationSuite) TestListSystemNotificationsUnauthorized() {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/notifications", nil)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(401, rec.Code, "Expected Unauthorized response for missing token")
}
