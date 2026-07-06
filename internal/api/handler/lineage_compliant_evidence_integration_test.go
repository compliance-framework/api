//go:build integration

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func TestLineageCompliantEvidence(t *testing.T) {
	suite.Run(t, new(LineageCompliantEvidenceSuite))
}

type LineageCompliantEvidenceSuite struct {
	tests.IntegrationTestSuite
}

func (suite *LineageCompliantEvidenceSuite) childrenOf(key string) []LineageNode {
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

// A fully-compliant control exposes its own compliance evidence as leaf children;
// a not-satisfied control does not.
func (suite *LineageCompliantEvidenceSuite) TestFullyCompliantControlShowsEvidence() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	catalog := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls: []relational.Control{
			{CatalogID: catID, ID: "pass-1", Title: "Compliant"},
			{CatalogID: catID, ID: "fail-1", Title: "Failing"},
		},
	}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)

	// A filter per control keyed by a distinct label.
	makeFilter := func(name, label, value, controlID string) {
		f := relational.Filter{
			Name: name,
			Filter: datatypes.NewJSONType(labelfilter.Filter{
				Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: label, Operator: "=", Value: value}},
			}),
		}
		suite.Require().NoError(suite.DB.Create(&f).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
			f.ID, catID, controlID).Error)
	}
	makeFilter("pass-filter", "ctrl", "pass", "pass-1")
	makeFilter("fail-filter", "ctrl", "fail", "fail-1")

	// Evidence: one satisfied stream labelled ctrl=pass, one not-satisfied ctrl=fail.
	mkEvidence := func(labelVal, state string, n int) uuid.UUID {
		stream := uuid.New()
		id := uuid.New()
		suite.Require().NoError(suite.DB.Create(&relational.Evidence{
			UUIDModel: relational.UUIDModel{ID: &id},
			UUID:      stream,
			Title:     fmt.Sprintf("ev-%d", n),
			Start:     now, End: now, Expires: &now,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: state, Reason: "auto"}),
		}).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO labels (name, value) VALUES ('ctrl', ?) ON CONFLICT DO NOTHING", labelVal).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', ?)", id, labelVal).Error)
		return stream
	}
	passStream := mkEvidence("pass", "satisfied", 1)
	mkEvidence("fail", "not-satisfied", 2)

	// The compliant control lists its evidence as a child.
	passKids := suite.childrenOf("control:" + catID.String() + "/pass-1")
	suite.Require().Len(passKids, 1)
	suite.Equal("evidence", passKids[0].NodeType)
	suite.Equal("has-evidence", passKids[0].Relationship)
	suite.Equal("evidence:"+passStream.String(), passKids[0].Key)
	suite.Equal("satisfied", passKids[0].Status)
	suite.NotNil(passKids[0].CollectedAt)

	// The failing control does NOT list evidence children.
	failKids := suite.childrenOf("control:" + catID.String() + "/fail-1")
	suite.Empty(failKids, "not-satisfied control has no evidence children")

	// The compliant control node (as a catalog child) reflects the evidence in its count.
	catKids := suite.childrenOf("catalog:" + catID.String())
	var passNode *LineageNode
	for i := range catKids {
		if catKids[i].ControlID == "pass-1" {
			passNode = &catKids[i]
		}
	}
	suite.Require().NotNil(passNode)
	suite.True(passNode.HasChildren)
	suite.Equal(1, passNode.ChildrenCount, "one evidence child counted")
}
