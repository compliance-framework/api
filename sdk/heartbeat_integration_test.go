//go:build integration

package sdk_test

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

func TestHeartbeatSDK(t *testing.T) {
	suite.Run(t, new(HeartbeatSDKIntegrationSuite))
}

type HeartbeatSDKIntegrationSuite struct {
	IntegrationBaseTestSuite
}

func (suite *HeartbeatSDKIntegrationSuite) TestCreateWithAgentAuth() {
	suite.Require().NoError(suite.Migrator.Refresh())

	client, err := suite.GetAuthenticatedSDKTestClient()
	suite.Require().NoError(err)

	err = client.Heartbeat.Create(context.Background(), types.Heartbeat{
		UUID:      uuid.New(),
		CreatedAt: time.Now().UTC(),
	})
	suite.Require().NoError(err)

	var count int64
	suite.Require().NoError(suite.DB.Model(&service.Heartbeat{}).Count(&count).Error)
	suite.Equal(int64(1), count)
}
