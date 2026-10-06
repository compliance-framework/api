//go:build integration

package handler

import "net/http"

// Regression (review #481/#482, fp a042387242aa): a NUL in a revert comment is a 400 (not a
// 500 from the insert), and no revision is created.
func (s *AgentConfigAdminIntegrationSuite) TestRegressionRevertCommentNULIsBadRequest() {
	s.save(`"0"`, `{"verbosity":1}`, 1)
	s.save(`"1"`, `{"verbosity":2}`, 2)
	rec := s.send(s.server, s.token, http.MethodPost, s.path("/config/revisions/1/revert"),
		[]byte(`{"comment":"a\u0000b"}`), "If-Match", `"2"`)
	s.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
	s.Equal(int64(2), s.revisionCount(*s.agent.ID))
}
