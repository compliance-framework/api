//go:build integration

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestLineageHierarchy(t *testing.T) {
	suite.Run(t, new(LineageHierarchySuite))
}

type LineageHierarchySuite struct {
	tests.IntegrationTestSuite
}

func (suite *LineageHierarchySuite) children(key string) []LineageNode {
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

// keys returns the sorted node keys, asserting none are duplicated.
func (suite *LineageHierarchySuite) keys(nodes []LineageNode) []string {
	seen := map[string]int{}
	out := []string{}
	for _, n := range nodes {
		seen[n.Key]++
		out = append(out, n.Key)
	}
	for k, c := range seen {
		suite.Equalf(1, c, "node %s appears %d times (duplicated)", k, c)
	}
	sort.Strings(out)
	return out
}

// Nested groups: catalog -> V4 -> {V4-1, V4-2} -> controls. Only V4 is a catalog
// child; sub-groups are reached by expanding V4, never promoted to catalog roots.
func (suite *LineageHierarchySuite) TestNestedGroups() {
	suite.Require().NoError(suite.Migrator.Refresh())

	now := time.Now().UTC()
	catID := uuid.New()
	cat := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "ASVS", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Groups: []relational.Group{{
			CatalogID: catID, ID: "V4", Title: "V4",
			Groups: []relational.Group{
				{CatalogID: catID, ID: "V4-1", Title: "V4.1", Controls: []relational.Control{
					{CatalogID: catID, ID: "V4.1.1", Title: "V4.1.1"},
					{CatalogID: catID, ID: "V4.1.2", Title: "V4.1.2"},
				}},
				{CatalogID: catID, ID: "V4-2", Title: "V4.2", Controls: []relational.Control{
					{CatalogID: catID, ID: "V4.2.1", Title: "V4.2.1"},
				}},
			},
		}},
	}
	suite.Require().NoError(suite.DB.Create(&cat).Error)

	suite.Equal(
		[]string{"group:" + catID.String() + "/V4"},
		suite.keys(suite.children("catalog:"+catID.String())),
		"only the top-level group V4 should be a catalog child",
	)
	// Expanding V4 yields its DIRECT sub-groups (as group nodes), not flattened
	// leaf controls — the tree mirrors the catalog's real hierarchy.
	suite.Equal(
		[]string{
			"group:" + catID.String() + "/V4-1",
			"group:" + catID.String() + "/V4-2",
		},
		suite.keys(suite.children("group:"+catID.String()+"/V4")),
	)
	// Controls appear one level deeper, under their own sub-group.
	suite.Equal(
		[]string{
			"control:" + catID.String() + "/V4.1.1",
			"control:" + catID.String() + "/V4.1.2",
		},
		suite.keys(suite.children("group:"+catID.String()+"/V4-1")),
	)
	suite.Equal(
		[]string{"control:" + catID.String() + "/V4.2.1"},
		suite.keys(suite.children("group:"+catID.String()+"/V4-2")),
	)

	// The V4 group node renders only its 2 direct sub-groups, but its metrics still
	// roll up over the WHOLE subtree (3 controls across both sub-groups).
	v4 := suite.children("catalog:" + catID.String())[0]
	suite.Equal(2, v4.ChildrenCount, "V4 has 2 direct children (its sub-groups)")
	suite.Equal(3, v4.Compliance.TotalControls, "V4 metrics span its full subtree")
}

// Flat catalog whose controls carry sub-controls: only the parent controls are
// catalog children — sub-controls must not leak to the catalog root.
func (suite *LineageHierarchySuite) TestFlatControlsWithSubControls() {
	suite.Require().NoError(suite.Migrator.Refresh())

	now := time.Now().UTC()
	catID := uuid.New()
	cat := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "ASVS", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}
	for _, p := range []string{"V4.1.1", "V4.1.2"} {
		parent := relational.Control{CatalogID: catID, ID: p, Title: p}
		parent.Controls = []relational.Control{{CatalogID: catID, ID: p + "-a", Title: p + "-a"}}
		cat.Controls = append(cat.Controls, parent)
	}
	suite.Require().NoError(suite.DB.Create(&cat).Error)

	suite.Equal(
		[]string{
			"control:" + catID.String() + "/V4.1.1",
			"control:" + catID.String() + "/V4.1.2",
		},
		suite.keys(suite.children("catalog:"+catID.String())),
		"sub-controls must not appear as catalog children",
	)
}

// seedASVS creates a catalog with the SHARED ASVS group/control ID scheme:
// group "V4" -> sub-group "V4-1" -> control "V4.1.1". Because these IDs are reused
// across catalogs, the polymorphic parent_id is not globally unique.
func (suite *LineageHierarchySuite) seedASVS(title string) uuid.UUID {
	now := time.Now().UTC()
	catID := uuid.New()
	cat := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: title, Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Groups: []relational.Group{{
			CatalogID: catID, ID: "V4", Title: "V4",
			Groups: []relational.Group{{
				CatalogID: catID, ID: "V4-1", Title: "V4.1",
				Controls: []relational.Control{{CatalogID: catID, ID: "V4.1.1", Title: "V4.1.1"}},
			}},
		}},
	}
	suite.Require().NoError(suite.DB.Create(&cat).Error)
	return catID
}

// The same ASVS group IDs imported into two catalogs must not bleed across: the
// unscoped polymorphic parent_id would otherwise match sibling rows in the other
// catalog and duplicate the tree.
func (suite *LineageHierarchySuite) TestSameIDsAcrossCatalogsDoNotBleed() {
	suite.Require().NoError(suite.Migrator.Refresh())

	catA := suite.seedASVS("ASVS import A")
	_ = suite.seedASVS("ASVS import B") // same group/control IDs, different catalog

	suite.Equal(
		[]string{"group:" + catA.String() + "/V4"},
		suite.keys(suite.children("catalog:"+catA.String())),
		"catalog A must show only its own top group, once",
	)
	suite.Equal(
		[]string{"group:" + catA.String() + "/V4-1"},
		suite.keys(suite.children("group:"+catA.String()+"/V4")),
		"V4's sub-groups must not include catalog B's V4-1",
	)
	suite.Equal(
		[]string{"control:" + catA.String() + "/V4.1.1"},
		suite.keys(suite.children("group:"+catA.String()+"/V4-1")),
		"V4-1's controls must not include catalog B's V4.1.1",
	)
}
