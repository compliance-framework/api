//go:build integration

package sdk_test

import (
	"context"
	"github.com/compliance-framework/configuration-service/sdk/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestObservationsSDK(t *testing.T) {
	suite.Run(t, new(ObservationsSDKIntegrationSuite))
}

type ObservationsSDKIntegrationSuite struct {
	IntegrationBaseTestSuite
}

func (suite *ObservationsSDKIntegrationSuite) TestCreateObservations() {
	suite.Run("Findings can be created through the SDK", func() {
		client := suite.GetSDKTestClient()
		err := client.Observations.Create(context.TODO(), []types.Observation{
			{
				UUID:        uuid.New(),
				ID:          uuid.New(),
				Title:       "Some Observation",
				Collected:   time.Now(),
				Description: "Foo",
				Remarks:     "Bar",
			},
		})
		suite.NoError(err)
	})
}
