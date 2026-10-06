//go:build integration

package handler

import "net/http"

// Regression (review #481, fp a042387242aa): a NUL in the revision comment is a 400 on
// PUT (not a 500 from the insert), and nothing is stored.
func (s *AgentConfigAdminIntegrationSuite) TestRegressionCommentNULIsBadRequest() {
	rec := s.send(s.server, s.token, http.MethodPut, s.path("/config"),
		[]byte(`{"overlay":{"verbosity":1},"comment":"a\u0000b"}`), "If-Match", `"0"`)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
	s.Equal(int64(0), s.revisionCount(*s.agent.ID))
}
