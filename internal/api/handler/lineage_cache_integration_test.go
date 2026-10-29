//go:build integration

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestLineageCache(t *testing.T) {
	suite.Run(t, new(LineageCacheSuite))
}

type LineageCacheSuite struct {
	tests.IntegrationTestSuite
}

func (suite *LineageCacheSuite) createCatalog(title string) uuid.UUID {
	now := time.Now().UTC()
	id := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &id},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: title, Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: id, ID: "c-1", Title: "Control"}},
	}).Error)
	return id
}

func (suite *LineageCacheSuite) roots(h *LineageHandler, query string) (*httptest.ResponseRecorder, []LineageNode) {
	req := httptest.NewRequest(http.MethodGet, "/api/lineage/roots"+query, nil)
	rec := httptest.NewRecorder()
	suite.Require().NoError(h.Roots(echo.New().NewContext(req, rec)))
	var resp struct {
		Data []LineageNode `json:"data"`
	}
	if rec.Code == http.StatusOK {
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	}
	return rec, resp.Data
}

func (suite *LineageCacheSuite) TestCachedDataIsReusedUntilRefresh() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.createCatalog("First")
	h := NewLineageHandler(zap.NewNop().Sugar(), suite.DB).
		WithEngineCache(&config.LineageConfig{CacheTTL: time.Hour, CacheMaxEntries: 4})

	rec, nodes := suite.roots(h, "")
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	suite.Len(nodes, 1)
	firstAt, err := time.Parse(time.RFC3339, rec.Header().Get(api.LineageGeneratedAtHeader))
	suite.Require().NoError(err)

	// A catalog added after the build is not visible until a refresh, and children of
	// the cached roots are served from the same data.
	second := suite.createCatalog("Second")
	rec, nodes = suite.roots(h, "")
	suite.Len(nodes, 1, "cached data is reused")
	suite.Equal(firstAt.Format(time.RFC3339), rec.Header().Get(api.LineageGeneratedAtHeader))

	childReq := httptest.NewRequest(http.MethodGet, "/x", nil)
	childRec := httptest.NewRecorder()
	ctx := echo.New().NewContext(childReq, childRec)
	ctx.SetPathValues(echo.PathValues{{Name: "key", Value: "catalog:" + second.String()}})
	suite.Require().NoError(h.Children(ctx))
	suite.Equal(http.StatusNotFound, childRec.Code, "the new catalog is not in the cached data")

	rec, nodes = suite.roots(h, "?refresh=true")
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	suite.Len(nodes, 2, "refresh rebuilds")
	refreshedAt, err := time.Parse(time.RFC3339, rec.Header().Get(api.LineageGeneratedAtHeader))
	suite.Require().NoError(err)
	suite.False(refreshedAt.Before(firstAt))

	_, nodes = suite.roots(h, "")
	suite.Len(nodes, 2, "later requests reuse the refreshed data")
}

func (suite *LineageCacheSuite) TestUncachedHandlerAlwaysRebuilds() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.createCatalog("First")
	h := NewLineageHandler(zap.NewNop().Sugar(), suite.DB)

	_, nodes := suite.roots(h, "")
	suite.Len(nodes, 1)
	suite.createCatalog("Second")
	rec, nodes := suite.roots(h, "")
	suite.Len(nodes, 2)
	suite.NotEmpty(rec.Header().Get(api.LineageGeneratedAtHeader))
}

func (suite *LineageCacheSuite) TestInvalidRefreshIsBadRequest() {
	suite.Require().NoError(suite.Migrator.Refresh())
	h := NewLineageHandler(zap.NewNop().Sugar(), suite.DB)

	rec, _ := suite.roots(h, "?refresh=soon")
	suite.Equal(http.StatusBadRequest, rec.Code)
}
