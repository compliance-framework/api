//go:build integration

package sdk_test

import (
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestResultsSDK(t *testing.T) {
	suite.Run(t, new(ResultsSDKIntegrationSuite))
}

type ResultsSDKIntegrationSuite struct {
	IntegrationBaseTestSuite
}

func (suite *ResultsSDKIntegrationSuite) TestCreateResult() {
	suite.Run("A result can be created through the SDK", func() {
		client := suite.GetSDKTestClient()
		response, err := client.Results.Create(uuid.New(), map[string]string{
			"type": "ssh",
		}, &oscaltypes113.Result{
			Title: "A Result to the API",
			Observations: &[]oscaltypes113.Observation{
				{
					Title: "A single observation",
				},
			},
		})
		suite.NoError(err)
		suite.Len(*response.Observations, 1)
		suite.Equal("A Result to the API", response.Title)
	})
}
