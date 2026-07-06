//go:build integration

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestLineageGrouping(t *testing.T) {
	suite.Run(t, new(LineageGroupingSuite))
}

type LineageGroupingSuite struct {
	tests.IntegrationTestSuite
}

func (suite *LineageGroupingSuite) childrenOf(key string) []LineageNode {
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

// A grouped control must appear ONLY under its group, never at the catalog level,
// while a genuinely ungrouped control appears at the catalog level.
func (suite *LineageGroupingSuite) TestGroupedControlsNotDuplicatedAtCatalogLevel() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	catalog := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		// One control directly on the catalog (ungrouped)...
		Controls: []relational.Control{{CatalogID: catID, ID: "top-1", Title: "Top Level"}},
		// ...and one control inside a group.
		Groups: []relational.Group{{
			CatalogID: catID,
			ID:        "grp",
			Title:     "Group",
			Controls:  []relational.Control{{CatalogID: catID, ID: "grp-1", Title: "Grouped"}},
		}},
	}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)

	// Catalog children = the group + ONLY the ungrouped control.
	kids := suite.childrenOf("catalog:" + catID.String())
	catControls := map[string]bool{}
	groupKeys := map[string]bool{}
	for _, n := range kids {
		switch n.NodeType {
		case "control":
			catControls[n.ControlID] = true
		case "group":
			groupKeys[n.GroupID] = true
		}
	}
	suite.True(groupKeys["grp"], "group appears at catalog level")
	suite.True(catControls["top-1"], "ungrouped control appears at catalog level")
	suite.False(catControls["grp-1"], "grouped control must NOT appear at catalog level")
	suite.Len(catControls, 1, "exactly one top-level control")

	// The grouped control appears under its group.
	groupKids := suite.childrenOf("group:" + catID.String() + "/grp")
	suite.Require().Len(groupKids, 1)
	suite.Equal("grp-1", groupKids[0].ControlID)
}
