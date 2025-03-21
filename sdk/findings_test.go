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

func TestFindingsSDK(t *testing.T) {
	suite.Run(t, new(FindingsSDKIntegrationSuite))
}

type FindingsSDKIntegrationSuite struct {
	IntegrationBaseTestSuite
}

func (suite *FindingsSDKIntegrationSuite) TestCreateFindings() {
	suite.Run("Findings can be created through the SDK", func() {
		client := suite.GetSDKTestClient()
		err := client.Findings.Create(context.TODO(), []types.Finding{
			{
				UUID:        uuid.New(),
				ID:          uuid.New(),
				Title:       "Some Finding",
				Collected:   time.Now(),
				Description: "Foo",
				Remarks:     "Bar",
				Labels: map[string]string{
					"type": "integration-test-finding",
				},
				Status: types.FindingStatus{
					State: "satisfied",
				},
			},
		})
		suite.NoError(err)
	})
}
