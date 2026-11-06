//go:build integration

package handler

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

func (suite *EvidenceApiIntegrationSuite) TestComplianceBadge() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.Config.StrictDisablePublicAgentEndpoints = false
	suite.Config.EvidenceBadgeMaxParams = 4
	now := time.Now().Add(-time.Hour)
	labels := []relational.Labels{
		{Name: "provider", Value: "azure"},
		{Name: "team", Value: "platform team"},
		{Name: "region", Value: "eu"},
		{Name: "_policy", Value: "hardening"},
	}
	create := func(stream uuid.UUID, state string, end time.Time, evidenceLabels []relational.Labels) {
		evidence := relational.Evidence{
			UUID: stream, Title: "Badge check", Start: end.Add(-time.Minute), End: end,
			Status: datatypes.NewJSONType(oscal.ObjectiveStatus{State: state}),
			Labels: evidenceLabels,
		}
		suite.Require().NoError(suite.DB.Create(&evidence).Error)
	}
	stream := uuid.New()
	create(stream, relational.EvidenceStatusNotSatisfied, now, labels)
	create(stream, relational.EvidenceStatusSatisfied, now.Add(time.Minute), labels)
	create(uuid.New(), relational.EvidenceStatusNotSatisfied, now, []relational.Labels{
		{Name: "provider", Value: "azure"}, {Name: "team", Value: "other"},
	})

	server := suite.setupServer()
	request := func(server *api.Server, query string, code int, status string) {
		rec := httptest.NewRecorder()
		server.E().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/evidence/badge.svg?"+query, nil))
		suite.Require().Equal(code, rec.Code, rec.Body.String())
		if code == http.StatusOK {
			suite.Equal("image/svg+xml; charset=utf-8", rec.Header().Get("Content-Type"))
			suite.Equal("no-store", rec.Header().Get("Cache-Control"))
			var svg struct{ XMLName xml.Name }
			suite.Require().NoError(xml.Unmarshal(rec.Body.Bytes(), &svg))
			suite.Equal("svg", svg.XMLName.Local)
			suite.Contains(rec.Body.String(), `aria-label="Compliance status: `+status+`"`)
		}
	}
	query := "provider=azure&team=platform+team&region=eu&_policy=hardening"
	request(server, query, http.StatusOK, "satisfied")
	request(server, "provider=missing", http.StatusOK, "unknown")
	request(server, "provider=azure&team=other", http.StatusOK, "not-satisfied")
	create(uuid.New(), relational.EvidenceStatusNotSatisfied, now, labels)
	request(server, query, http.StatusOK, "not-satisfied")
	request(server, "provider=azure&provider=azure", http.StatusBadRequest, "")
	request(server, "", http.StatusBadRequest, "")

	suite.Config.EvidenceBadgeMaxParams = 0
	request(suite.setupServer(), query, http.StatusBadRequest, "")
	suite.Config.EvidenceBadgeMaxParams = 1
	server = suite.setupServer()
	request(server, "provider=azure", http.StatusOK, "not-satisfied")
	request(server, "provider=azure&team=other", http.StatusBadRequest, "")
}
