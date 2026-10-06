//go:build integration

package handler

import (
	"net/http"
	"sync"

	"gorm.io/gorm"
)

// Regression (review #479, fp 935fac26ca05): a poll that ends in 304 must not read the
// overlay column; the overlay is only loaded when the agent's ETag is stale.
func (s *AgentConfigSyncIntegrationSuite) TestRegressionNotModifiedPollSkipsOverlay() {
	a := s.newAgent("poll-agent")
	s.createRevision(*a.agent.ID, 0, `{"verbosity":1}`)
	rec := s.getConfig(a.token, "")
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	etag := rec.Header().Get("ETag")
	s.Require().NotEmpty(etag)

	var (
		mu      sync.Mutex
		queries []string
	)
	const cb = "regression:record-revision-queries"
	s.Require().NoError(s.DB.Callback().Query().After("gorm:query").Register(cb, func(db *gorm.DB) {
		if db.Statement != nil && db.Statement.Table == "ccf_agent_config_revisions" {
			mu.Lock()
			queries = append(queries, db.Statement.SQL.String())
			mu.Unlock()
		}
	}))
	defer func() { s.Require().NoError(s.DB.Callback().Query().Remove(cb)) }()

	rec = s.getConfig(a.token, etag)
	s.Require().Equal(http.StatusNotModified, rec.Code, rec.Body.String())

	mu.Lock()
	defer mu.Unlock()
	s.Require().NotEmpty(queries, "the poll reads the current revision")
	for _, q := range queries {
		s.NotContains(q, "SELECT *", q)
		s.NotContains(q, "overlay", q)
	}
}
