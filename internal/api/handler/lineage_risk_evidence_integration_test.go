//go:build integration

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func TestLineageRiskEvidence(t *testing.T) {
	suite.Run(t, new(LineageRiskEvidenceSuite))
}

type LineageRiskEvidenceSuite struct {
	tests.IntegrationTestSuite
}

func (suite *LineageRiskEvidenceSuite) childrenOf(key string) []LineageNode {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("key")
	ctx.SetParamValues(key)
	suite.Require().NoError(NewLineageHandler(zap.NewNop().Sugar(), suite.DB).Children(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []LineageNode `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// A control expands to its linked risks; a risk expands to its latest evidence
// per linked stream.
func (suite *LineageRiskEvidenceSuite) TestControlToRiskToEvidence() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	catalog := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: catID, ID: "ac-1", Title: "Access Control"}},
	}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)

	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		Metadata:  relational.Metadata{Title: "Prod SSP", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)

	// A risk (high x high = 16) linked to ac-1.
	high := "high"
	risk := riskrel.Risk{
		Title:       "Test Risk",
		Description: "d",
		Status:      string(riskrel.RiskStatusOpen),
		SSPID:       sspID,
		Likelihood:  &high,
		Impact:      &high,
		SourceType:  string(riskrel.RiskSourceTypeManual),
	}
	suite.Require().NoError(suite.DB.Create(&risk).Error)
	suite.Require().NoError(suite.DB.Create(&riskrel.RiskControlLink{
		RiskID: *risk.ID, CatalogID: catID, ControlID: "ac-1",
	}).Error)

	// One evidence stream with two rows (latest wins), linked to the risk.
	streamID := uuid.New()
	older := uuid.New()
	newer := uuid.New()
	suite.Require().NoError(suite.DB.Create(&[]relational.Evidence{
		{UUIDModel: relational.UUIDModel{ID: &older}, UUID: streamID, Title: "ev", Start: now.Add(-time.Hour), End: now.Add(-time.Hour),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"})},
		{UUIDModel: relational.UUIDModel{ID: &newer}, UUID: streamID, Title: "ev", Start: now, End: now,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"})},
	}).Error)
	suite.Require().NoError(suite.DB.Create(&riskrel.RiskEvidenceLink{
		RiskID: *risk.ID, EvidenceID: streamID,
	}).Error)

	// control -> risk
	kids := suite.childrenOf("control:" + catID.String() + "/ac-1")
	var riskNodes []LineageNode
	for _, n := range kids {
		if n.NodeType == "risk" {
			riskNodes = append(riskNodes, n)
		}
	}
	suite.Require().Len(riskNodes, 1, "one risk under the control")
	rn := riskNodes[0]
	suite.Equal("risk:"+risk.ID.String(), rn.Key)
	suite.Equal("has-risk", rn.Relationship)
	suite.Equal("Test Risk", rn.Title)
	suite.Equal("open", rn.Status)
	suite.Require().NotNil(rn.Score)
	suite.Equal(16, *rn.Score, "high x high")
	suite.Equal("high", rn.Severity, "score 16 bands to high")
	suite.Equal("high", rn.Likelihood)
	suite.Equal("high", rn.Impact)
	suite.Require().NotNil(rn.LinkedEvidenceCount)
	suite.Equal(1, *rn.LinkedEvidenceCount)
	suite.NotNil(rn.FirstSeenAt)
	suite.True(rn.HasChildren)
	suite.Equal(1, rn.ChildrenCount, "one linked stream")
	suite.Equal(sspID.String(), rn.RiskSSPID, "risk nodes carry their owning SSP id")
	suite.Equal("Prod SSP", rn.RiskSSPTitle, "risk nodes carry their owning SSP title in the global view")

	// risk -> evidence (latest per stream: one node, satisfied)
	evs := suite.childrenOf(rn.Key)
	suite.Require().Len(evs, 1, "one latest-evidence node per stream")
	ev := evs[0]
	suite.Equal("evidence", ev.NodeType)
	suite.Equal("has-evidence", ev.Relationship)
	suite.Equal("evidence:"+streamID.String(), ev.Key)
	suite.Equal("satisfied", ev.Status, "latest row wins")
	suite.NotNil(ev.CollectedAt, "collectedAt is the latest evidence end time")

	// evidence is a leaf
	suite.Empty(suite.childrenOf(evs[0].Key))
}

// Closed risks are dropped from the lineage entirely; remediated (and other) risks
// stay as nodes.
func (suite *LineageRiskEvidenceSuite) TestClosedRisksAreNotNodes() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: catID, ID: "ac-1", Title: "Access Control"}},
	}).Error)

	mkRisk := func(title, status string) {
		r := riskrel.Risk{
			Title: title, Description: "d", Status: status, SSPID: uuid.New(),
			SourceType: string(riskrel.RiskSourceTypeManual), FirstSeenAt: now, LastSeenAt: now,
		}
		suite.Require().NoError(suite.DB.Create(&r).Error)
		suite.Require().NoError(suite.DB.Create(&riskrel.RiskControlLink{RiskID: *r.ID, CatalogID: catID, ControlID: "ac-1"}).Error)
	}
	mkRisk("Open Risk", string(riskrel.RiskStatusOpen))
	mkRisk("Remediated Risk", string(riskrel.RiskStatusRemediated))
	mkRisk("Closed Risk", string(riskrel.RiskStatusClosed))

	titles := map[string]bool{}
	for _, n := range suite.childrenOf("control:" + catID.String() + "/ac-1") {
		if n.NodeType == "risk" {
			titles[n.Title] = true
		}
	}
	suite.True(titles["Open Risk"], "open risk is a node")
	suite.True(titles["Remediated Risk"], "remediated risk stays a node")
	suite.False(titles["Closed Risk"], "closed risk must not appear as a node")
	suite.Len(titles, 2)

	// The child count matches the visible risks (closed excluded).
	var ac1 *LineageNode
	for _, n := range suite.childrenOf("catalog:" + catID.String()) {
		if n.ControlID == "ac-1" {
			n := n
			ac1 = &n
		}
	}
	suite.Require().NotNil(ac1)
	suite.Equal(2, ac1.ChildrenCount, "child count excludes the closed risk")
}
