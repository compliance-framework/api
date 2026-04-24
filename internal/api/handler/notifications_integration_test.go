//go:build integration

package handler

import (
	"context"
	"encoding/json"
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

func (suite *NotificationsApiIntegrationSuite) TestListSystemNotifications() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

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

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/notifications", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListSystemNotifications")

	var response GenericDataListResponse[systemNotificationResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
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
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	suite.Require().NoError(suite.DB.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeTaskAvailable,
		Provider:         notification.DeliveryChannelEmail,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				emailprovider.AddressKeyEmail: "alerts@example.com",
			},
		}),
	}).Error)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/notifications", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListSystemNotifications")

	var response GenericDataListResponse[systemNotificationResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal notifications response")
	suite.Require().Len(response.Data, 1)

	suite.Equal("TASK_AVAILABLE", response.Data[0].Name)
	suite.Equal([]configuredSystemDestinationResponse{
		{ProviderType: "email", DestinationTarget: "alerts@example.com"},
	}, response.Data[0].ConfiguredDestinations)
}

func (suite *NotificationsApiIntegrationSuite) TestListSystemNotificationsReturnsEmptyDataWhenNoConfigurationsExist() {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/notifications", nil)
	req.Header.Set("Authorization", "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(200, rec.Code, "Expected OK response for ListSystemNotifications")

	var response GenericDataListResponse[systemNotificationResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err, "Failed to unmarshal notifications response")
	suite.Empty(response.Data)
}

func (suite *NotificationsApiIntegrationSuite) TestListSystemNotificationsUnauthorized() {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/notifications", nil)

	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(401, rec.Code, "Expected Unauthorized response for missing token")
}
