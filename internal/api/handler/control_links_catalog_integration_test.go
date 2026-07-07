//go:build integration

package handler

import (
	"bytes"
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

func TestCatalogControlLinks(t *testing.T) {
	suite.Run(t, new(CatalogControlLinksSuite))
}

type CatalogControlLinksSuite struct {
	tests.IntegrationTestSuite
}

func (suite *CatalogControlLinksSuite) handler() *ControlLinkHandler {
	return NewControlLinkHandler(zap.NewNop().Sugar(), suite.DB)
}

// call invokes a handler method with an optional JSON body and raw query string,
// returning the recorder. Mirrors the direct-handler style used by the lineage
// integration tests (no auth middleware; actorUserID tolerates absent claims).
func (suite *CatalogControlLinksSuite) call(method, query string, body any, fn func(echo.Context) error) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		suite.Require().NoError(err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	target := "/x"
	if query != "" {
		target += "?" + query
	}
	e := echo.New()
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	suite.Require().NoError(fn(ctx))
	return rec
}

func (suite *CatalogControlLinksSuite) countLinks() int64 {
	var n int64
	suite.Require().NoError(suite.DB.Model(&relational.ControlLink{}).Count(&n).Error)
	return n
}

func (suite *CatalogControlLinksSuite) seedCatalog(ctype string, title string, topControls []string, groupControls []string) uuid.UUID {
	now := time.Now().UTC()
	catID := uuid.New()
	cat := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: ctype,
		Metadata:    relational.Metadata{Title: title, Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}
	for _, id := range topControls {
		cat.Controls = append(cat.Controls, relational.Control{CatalogID: catID, ID: id, Title: id})
	}
	if len(groupControls) > 0 {
		grp := relational.Group{CatalogID: catID, ID: "grp", Title: "Group"}
		for _, id := range groupControls {
			grp.Controls = append(grp.Controls, relational.Control{CatalogID: catID, ID: id, Title: id})
		}
		cat.Groups = append(cat.Groups, grp)
	}
	suite.Require().NoError(suite.DB.Create(&cat).Error)
	return catID
}

// The catalog-level API fans a whole policy catalog out to a single standard
// control, aggregates it back, re-syncs to new controls, and deletes the set.
func (suite *CatalogControlLinksSuite) TestCatalogLinkLifecycle() {
	suite.Require().NoError(suite.Migrator.Refresh())

	// Policy catalog: one top-level + one grouped control (both must be linked).
	policyCat := suite.seedCatalog(relational.CatalogTypePolicy, "Policy", []string{"pol-top"}, []string{"pol-grouped"})
	// Standard catalog with the target control.
	stdCat := suite.seedCatalog(relational.CatalogTypeStandard, "Std", []string{"std-1"}, nil)

	body := catalogLinkRequest{
		SourceCatalogID:  policyCat,
		Target:           controlRefRequest{CatalogID: stdCat, ControlID: "std-1"},
		RelationshipType: relational.RelationshipImplements,
	}

	// Create: fan out to BOTH policy controls (top-level + grouped).
	rec := suite.call(http.MethodPost, "", body, suite.handler().CreateCatalogLink)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var created struct {
		Data catalogLinkResponse `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &created))
	suite.Equal(2, created.Data.Created)
	suite.EqualValues(2, suite.countLinks())

	// Idempotent: re-create skips both existing rows.
	rec = suite.call(http.MethodPost, "", body, suite.handler().CreateCatalogLink)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &created))
	suite.Equal(0, created.Data.Created)
	suite.Equal(2, created.Data.Skipped)
	suite.EqualValues(2, suite.countLinks())

	// List aggregates the fan-out back into one catalog-level link with count 2.
	rec = suite.call(http.MethodGet, "sourceCatalogId="+policyCat.String(), nil, suite.handler().ListCatalogLinks)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var listed struct {
		Data []catalogLinkSummary `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &listed))
	suite.Require().Len(listed.Data, 1)
	suite.Equal(policyCat, listed.Data[0].SourceCatalogID)
	suite.Equal(stdCat, listed.Data[0].TargetCatalogID)
	suite.Equal("std-1", listed.Data[0].TargetControlID)
	suite.Equal(relational.RelationshipImplements, listed.Data[0].RelationshipType)
	suite.Equal(2, listed.Data[0].ControlCount)

	// Add a control to the policy catalog, then Sync picks it up (2 deleted, 3 created).
	suite.Require().NoError(suite.DB.Create(&relational.Control{CatalogID: policyCat, ID: "pol-new", Title: "New"}).Error)
	rec = suite.call(http.MethodPut, "", body, suite.handler().SyncCatalogLink)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var synced struct {
		Data catalogLinkResponse `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &synced))
	suite.Equal(3, synced.Data.Created)
	suite.Equal(2, synced.Data.Deleted)
	suite.EqualValues(3, suite.countLinks())

	// Delete removes the whole fan-out set.
	del := "sourceCatalogId=" + policyCat.String() +
		"&targetCatalogId=" + stdCat.String() +
		"&targetControlId=std-1&relationshipType=" + relational.RelationshipImplements
	rec = suite.call(http.MethodDelete, del, nil, suite.handler().DeleteCatalogLink)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var deleted struct {
		Data catalogLinkResponse `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &deleted))
	suite.Equal(3, deleted.Data.Deleted)
	suite.EqualValues(0, suite.countLinks())
}

// A relationship that violates the vocabulary matrix is rejected as 422 and writes
// nothing (standard -> policy is not a valid "documents" edge).
func (suite *CatalogControlLinksSuite) TestCatalogLinkInvalidRelationship() {
	suite.Require().NoError(suite.Migrator.Refresh())

	stdCat := suite.seedCatalog(relational.CatalogTypeStandard, "Std", []string{"std-1"}, nil)
	policyCat := suite.seedCatalog(relational.CatalogTypePolicy, "Policy", []string{"pol-1"}, nil)

	body := catalogLinkRequest{
		SourceCatalogID:  stdCat,
		Target:           controlRefRequest{CatalogID: policyCat, ControlID: "pol-1"},
		RelationshipType: relational.RelationshipDocuments, // documents requires procedure -> policy
	}
	rec := suite.call(http.MethodPost, "", body, suite.handler().CreateCatalogLink)
	suite.Require().Equal(http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	suite.EqualValues(0, suite.countLinks())
}
