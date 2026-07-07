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

func TestLineageLinkCat(t *testing.T) {
	suite.Run(t, new(LineageLinkCatSuite))
}

type LineageLinkCatSuite struct {
	tests.IntegrationTestSuite
}

func (suite *LineageLinkCatSuite) childrenOf(key string) []LineageNode {
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

func (suite *LineageLinkCatSuite) roots() []LineageNode {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	suite.Require().NoError(NewLineageHandler(zap.NewNop().Sugar(), suite.DB).Roots(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []LineageNode `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func (suite *LineageLinkCatSuite) seedCatalog(ctype, title string, controls ...string) uuid.UUID {
	now := time.Now().UTC()
	catID := uuid.New()
	cat := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: ctype,
		Metadata:    relational.Metadata{Title: title, Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}
	for _, id := range controls {
		cat.Controls = append(cat.Controls, relational.Control{CatalogID: catID, ID: id, Title: id})
	}
	suite.Require().NoError(suite.DB.Create(&cat).Error)
	return catID
}

// Expanding a standard control returns a synthetic policy-catalog node (grouping
// the policy controls that implement it), and expanding THAT node returns the
// policy controls themselves — i.e. Standard-Control -> Policy-Catalog -> Controls.
func (suite *LineageLinkCatSuite) TestControlExpandsToLinkedCatalogNode() {
	suite.Require().NoError(suite.Migrator.Refresh())

	stdCat := suite.seedCatalog(relational.CatalogTypeStandard, "Std", "std-1")
	policyCat := suite.seedCatalog(relational.CatalogTypePolicy, "Policy", "pol-a", "pol-b")

	// Both policy controls implement the standard control.
	for _, ctrl := range []string{"pol-a", "pol-b"} {
		suite.Require().NoError(suite.DB.Create(&relational.ControlLink{
			SourceCatalogID:  policyCat,
			SourceControlID:  ctrl,
			TargetCatalogID:  stdCat,
			TargetControlID:  "std-1",
			RelationshipType: relational.RelationshipImplements,
		}).Error)
	}

	// The standard control's children include ONE policy-catalog grouping node,
	// not the two policy controls directly.
	kids := suite.childrenOf("control:" + stdCat.String() + "/std-1")
	var linkcat *LineageNode
	for i := range kids {
		if kids[i].NodeType == "policy-catalog" {
			linkcat = &kids[i]
		}
		suite.NotEqual("policy-control", kids[i].NodeType, "policy controls must not appear directly under the standard control")
	}
	suite.Require().NotNil(linkcat, "expected a policy-catalog grouping node")
	suite.Equal("implements", linkcat.Relationship)
	suite.Equal(policyCat.String(), linkcat.CatalogID)
	suite.Equal("Policy", linkcat.Title)
	suite.True(linkcat.HasChildren)
	suite.Equal(2, linkcat.ChildrenCount)

	// Expanding the grouping node yields the two policy controls.
	grandkids := suite.childrenOf(linkcat.Key)
	got := map[string]bool{}
	for _, n := range grandkids {
		suite.Equal("policy-control", n.NodeType)
		got[n.ControlID] = true
	}
	suite.True(got["pol-a"] && got["pol-b"], "both policy controls appear under the catalog node, got %v", got)
}

// An inactive catalog is omitted from /roots but still surfaces as a control-link
// child of an active catalog's control — hiding it from the top level without
// severing its lineage relationships.
func (suite *LineageLinkCatSuite) TestInactiveCatalogHiddenFromRootsButLinkable() {
	suite.Require().NoError(suite.Migrator.Refresh())

	stdCat := suite.seedCatalog(relational.CatalogTypeStandard, "Std", "std-1")
	policyCat := suite.seedCatalog(relational.CatalogTypePolicy, "Draft Policy", "pol-a")

	// Mark the policy catalog inactive (still in development).
	suite.Require().NoError(suite.DB.Model(&relational.Catalog{}).
		Where("id = ?", policyCat).Update("active", false).Error)

	// The policy control implements the standard control.
	suite.Require().NoError(suite.DB.Create(&relational.ControlLink{
		SourceCatalogID:  policyCat,
		SourceControlID:  "pol-a",
		TargetCatalogID:  stdCat,
		TargetControlID:  "std-1",
		RelationshipType: relational.RelationshipImplements,
	}).Error)

	// Roots include the active standard catalog but NOT the inactive policy catalog.
	rootIDs := map[string]bool{}
	for _, r := range suite.roots() {
		rootIDs[r.CatalogID] = true
	}
	suite.True(rootIDs[stdCat.String()], "active standard catalog must be a root")
	suite.False(rootIDs[policyCat.String()], "inactive policy catalog must not be a root")

	// ...but the inactive catalog still appears as a linkcat child of the std control.
	kids := suite.childrenOf("control:" + stdCat.String() + "/std-1")
	var linkcat *LineageNode
	for i := range kids {
		if kids[i].NodeType == "policy-catalog" && kids[i].CatalogID == policyCat.String() {
			linkcat = &kids[i]
		}
	}
	suite.Require().NotNil(linkcat, "inactive policy catalog must still appear as a control-link child")
	suite.Equal("Draft Policy", linkcat.Title)
}
