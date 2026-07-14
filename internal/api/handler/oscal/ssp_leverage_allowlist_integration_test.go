//go:build integration

package oscal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
)

// SubscribeAllowlistIntegrationSuite exercises BCH-1342's ticket AC end to end, through a
// real cedar-driven PEP: a downstream SSP not on an offering's allow-list is denied
// subscribe (403) even holding the contributor role (which alone would otherwise pass
// both the ssp-export-offering:subscribe and ssp:update checks); an allow-listed
// downstream succeeds; an offering with no allow-list set keeps today's type-level
// default (any downstream may subscribe).
type SubscribeAllowlistIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

func TestSubscribeAllowlistIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SubscribeAllowlistIntegrationSuite))
}

func (suite *SubscribeAllowlistIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.server = newCedarServer(&suite.IntegrationTestSuite)
}

// publishedOfferingFixture creates an upstream SSP, publishes a one-item offering on it as
// contributorToken, and returns (upstreamSSPID, offeringID, itemID).
func (suite *SubscribeAllowlistIntegrationSuite) publishedOfferingFixture(contributorToken string) (upstreamSSPID, offeringID, itemID string) {
	componentUUID := uuid.New().String()
	// The offered capability has to be a real statement-anchored export inside this SSP: an item
	// now requires a statementId, and the whole tuple must resolve.
	acOne := exportedStatement{ControlID: "ac-1", StatementID: "ac-1_stmt.a", ProvidedUUID: uuid.New().String()}
	ssp := sspWithStatementExports(componentUUID, acOne)
	rec := authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", "/api/oscal/system-security-plans", contributorToken, ssp)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	upstreamSSPID = ssp.UUID

	rec = authedRequest(&suite.IntegrationTestSuite, suite.server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings", upstreamSSPID),
		contributorToken,
		map[string]string{"title": "Allow-list test offering", "description": "one leverageable control"},
	)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var created handler.GenericDataResponse[relational.SSPExportOffering]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &created))
	offeringID = created.Data.ID.String()

	itemPath := fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/items", upstreamSSPID, offeringID)
	rec = authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", itemPath, contributorToken,
		offeringItemBody(componentUUID, acOne))
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var item handler.GenericDataResponse[relational.SSPExportOfferingItem]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &item))
	itemID = item.Data.ID.String()

	publishPath := fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/publish", upstreamSSPID, offeringID)
	rec = authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", publishPath, contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	return upstreamSSPID, offeringID, itemID
}

func (suite *SubscribeAllowlistIntegrationSuite) createDownstreamSSP(contributorToken string) string {
	ssp := minimalSSP(uuid.New().String())
	rec := authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", "/api/oscal/system-security-plans", contributorToken, ssp)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	return ssp.UUID
}

func (suite *SubscribeAllowlistIntegrationSuite) subscribeRequestBody(downstreamSSPID, itemID string) map[string]any {
	return map[string]any{
		"downstreamSspId": downstreamSSPID,
		"leveragedAuthorization": map[string]string{
			"title":     "Trust",
			"partyUuid": uuid.New().String(),
		},
		"items": []map[string]any{
			{"itemId": itemID, "satisfiedResponsibilityUuids": []string{}},
		},
	}
}

func (suite *SubscribeAllowlistIntegrationSuite) TestNonAllowListedDownstreamDeniedEvenWithContributorRole() {
	contributorToken := createRoledUser(&suite.IntegrationTestSuite, "upstream-curator@example.com", "contributor")
	upstreamSSPID, offeringID, itemID := suite.publishedOfferingFixture(contributorToken)

	allowedDownstreamSSPID := suite.createDownstreamSSP(contributorToken)
	addAllowlistPath := fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/allowed-downstreams", upstreamSSPID, offeringID)
	rec := authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", addAllowlistPath, contributorToken,
		map[string]string{"downstreamSspId": allowedDownstreamSSPID})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// A different downstream, held by a user who also has the contributor role (so
	// ssp-export-offering:subscribe and ssp:update both pass) — the allow-list is the only
	// thing that should block this request.
	downstreamContributorToken := createRoledUser(&suite.IntegrationTestSuite, "downstream-contributor@example.com", "contributor")
	nonListedDownstreamSSPID := suite.createDownstreamSSP(downstreamContributorToken)

	subscribePath := fmt.Sprintf("/api/oscal/ssp-export-offerings/%s/subscribe", offeringID)
	rec = authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", subscribePath, downstreamContributorToken,
		suite.subscribeRequestBody(nonListedDownstreamSSPID, itemID))
	suite.Require().Equal(http.StatusForbidden, rec.Code, rec.Body.String())
}

func (suite *SubscribeAllowlistIntegrationSuite) TestAllowListedDownstreamCanSubscribe() {
	contributorToken := createRoledUser(&suite.IntegrationTestSuite, "upstream-curator2@example.com", "contributor")
	upstreamSSPID, offeringID, itemID := suite.publishedOfferingFixture(contributorToken)

	downstreamContributorToken := createRoledUser(&suite.IntegrationTestSuite, "downstream-contributor2@example.com", "contributor")
	downstreamSSPID := suite.createDownstreamSSP(downstreamContributorToken)

	addAllowlistPath := fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/allowed-downstreams", upstreamSSPID, offeringID)
	rec := authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", addAllowlistPath, contributorToken,
		map[string]string{"downstreamSspId": downstreamSSPID})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	subscribePath := fmt.Sprintf("/api/oscal/ssp-export-offerings/%s/subscribe", offeringID)
	rec = authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", subscribePath, downstreamContributorToken,
		suite.subscribeRequestBody(downstreamSSPID, itemID))
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
}

func (suite *SubscribeAllowlistIntegrationSuite) TestNoAllowListSetKeepsTypeLevelDefault() {
	contributorToken := createRoledUser(&suite.IntegrationTestSuite, "upstream-curator3@example.com", "contributor")
	_, offeringID, itemID := suite.publishedOfferingFixture(contributorToken)

	downstreamContributorToken := createRoledUser(&suite.IntegrationTestSuite, "downstream-contributor3@example.com", "contributor")
	downstreamSSPID := suite.createDownstreamSSP(downstreamContributorToken)

	// No allowed-downstreams entries added for this offering at all.
	subscribePath := fmt.Sprintf("/api/oscal/ssp-export-offerings/%s/subscribe", offeringID)
	rec := authedRequest(&suite.IntegrationTestSuite, suite.server, "POST", subscribePath, downstreamContributorToken,
		suite.subscribeRequestBody(downstreamSSPID, itemID))
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
}
