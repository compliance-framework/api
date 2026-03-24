//go:build integration

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// BCH-1186: POST /risks/:id/promote-to-poam integration tests
// ---------------------------------------------------------------------------

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_HappyPath() {
	sspID := suite.newSSPID()

	// Create a risk in investigating status, then accept it.
	created := suite.createRisk(map[string]any{
		"title":       "Unencrypted data at rest",
		"description": "Sensitive data stored without encryption",
		"ssp-id":      sspID,
		"status":      "investigating",
		"likelihood":  "high",
		"impact":      "critical",
	})

	acceptDeadline := time.Now().Add(30 * 24 * time.Hour).UTC()
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "accepted pending encryption rollout",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	// Promote to POAM with full payload.
	deadline := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{
		"title":            "Encrypt data at rest — remediation plan",
		"deadline":         deadline.Format(time.RFC3339),
		"resourceRequired": "3 engineer days",
		"pocName":          "Jane Smith",
		"pocEmail":         "jane@example.com",
		"milestones": []map[string]any{
			{"title": "Identify all unencrypted data stores", "orderIndex": 0},
			{"title": "Apply AES-256 encryption to all stores", "orderIndex": 1},
		},
	})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusCreated, promoteRec.Code, "promote-to-poam should return 201")

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(promoteRec.Body.Bytes(), &poamResp))

	// Verify POAM item fields.
	require.Equal(suite.T(), "Encrypt data at rest — remediation plan", poamResp.Data.Title)
	require.Equal(suite.T(), "Sensitive data stored without encryption", poamResp.Data.Description)
	require.Equal(suite.T(), "open", poamResp.Data.Status)
	require.Equal(suite.T(), "risk-promotion", poamResp.Data.SourceType)
	require.NotNil(suite.T(), poamResp.Data.CreatedFromRiskID)
	require.Equal(suite.T(), created.ID.String(), poamResp.Data.CreatedFromRiskID.String())
	require.NotNil(suite.T(), poamResp.Data.PlannedCompletionDate)
	require.WithinDuration(suite.T(), deadline, *poamResp.Data.PlannedCompletionDate, time.Second)
	require.NotNil(suite.T(), poamResp.Data.PocName)
	require.Equal(suite.T(), "Jane Smith", *poamResp.Data.PocName)
	require.NotNil(suite.T(), poamResp.Data.PocEmail)
	require.Equal(suite.T(), "jane@example.com", *poamResp.Data.PocEmail)
	require.NotNil(suite.T(), poamResp.Data.ResourceRequired)
	require.Equal(suite.T(), "3 engineer days", *poamResp.Data.ResourceRequired)

	// Verify milestones.
	require.Len(suite.T(), poamResp.Data.Milestones, 2)
	require.Equal(suite.T(), "Identify all unencrypted data stores", poamResp.Data.Milestones[0].Title)
	require.Equal(suite.T(), "Apply AES-256 encryption to all stores", poamResp.Data.Milestones[1].Title)

	// Verify risk link was created.
	require.Len(suite.T(), poamResp.Data.RiskLinks, 1)
	require.Equal(suite.T(), created.ID.String(), poamResp.Data.RiskLinks[0].RiskID.String())

	// Verify risk_event(poam_promoted) was emitted.
	var promotedEvents int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypePoamPromoted)).
		Count(&promotedEvents).Error)
	require.Equal(suite.T(), int64(1), promotedEvents)
}

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_DefaultsFromRisk() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Weak password policy",
		"description": "Password complexity rules not enforced",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	acceptDeadline := time.Now().Add(14 * 24 * time.Hour).UTC()
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "accepted pending policy update",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	// Promote with empty body — title and description should default from risk.
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusCreated, promoteRec.Code)

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(promoteRec.Body.Bytes(), &poamResp))

	// Title and description should default to the risk's values.
	require.Equal(suite.T(), "Weak password policy", poamResp.Data.Title)
	require.Equal(suite.T(), "Password complexity rules not enforced", poamResp.Data.Description)
	require.Equal(suite.T(), "open", poamResp.Data.Status)
	require.Equal(suite.T(), "risk-promotion", poamResp.Data.SourceType)
}

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_RejectsNonAcceptedRisk() {
	sspID := suite.newSSPID()

	// Risk in "open" status — not risk-accepted.
	created := suite.createRisk(map[string]any{
		"title":       "Open risk",
		"description": "Not yet accepted",
		"ssp-id":      sspID,
		"status":      "open",
	})

	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusUnprocessableEntity, promoteRec.Code, "should return 422 for non-accepted risk")

	// Risk in "investigating" status — also not risk-accepted.
	investigating := suite.createRisk(map[string]any{
		"title":       "Investigating risk",
		"description": "Still being investigated",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	promoteRec2, promoteReq2 := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", investigating.ID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec2, promoteReq2)
	require.Equal(suite.T(), http.StatusUnprocessableEntity, promoteRec2.Code, "should return 422 for investigating risk")
}

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_RejectsActivePoamAlreadyLinked() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Duplicate promotion risk",
		"description": "Testing re-promotion guard",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	acceptDeadline := time.Now().Add(14 * 24 * time.Hour).UTC()
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "accepted",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	// First promotion should succeed.
	firstRec, firstReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(firstRec, firstReq)
	require.Equal(suite.T(), http.StatusCreated, firstRec.Code)

	// Second promotion should fail — active POAM item already linked.
	secondRec, secondReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(secondRec, secondReq)
	require.Equal(suite.T(), http.StatusUnprocessableEntity, secondRec.Code, "should return 422 when active POAM already linked")
}

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_RejectsNotFound() {
	nonExistentID := uuid.New()
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", nonExistentID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusNotFound, promoteRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_SSPScoped_HappyPath() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "SSP-scoped promotion risk",
		"description": "Testing SSP-scoped promote endpoint",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	acceptDeadline := time.Now().Add(14 * 24 * time.Hour).UTC()
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "accepted for SSP-scoped test",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	// Promote via SSP-scoped endpoint.
	sspPromoteRec, sspPromoteReq := suite.authedRequest(
		http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/promote-to-poam", sspID, created.ID),
		map[string]any{"pocName": "SSP Owner"},
	)
	suite.server.E().ServeHTTP(sspPromoteRec, sspPromoteReq)
	require.Equal(suite.T(), http.StatusCreated, sspPromoteRec.Code)

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(sspPromoteRec.Body.Bytes(), &poamResp))
	require.Equal(suite.T(), "SSP-scoped promotion risk", poamResp.Data.Title)
	require.NotNil(suite.T(), poamResp.Data.PocName)
	require.Equal(suite.T(), "SSP Owner", *poamResp.Data.PocName)
}

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_SSPScoped_RejectsWrongSSP() {
	sspID := suite.newSSPID()
	wrongSSPID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Wrong SSP risk",
		"description": "Risk belongs to a different SSP",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	acceptDeadline := time.Now().Add(14 * 24 * time.Hour).UTC()
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "accepted",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	// Attempt to promote via wrong SSP — should return 404.
	wrongSSPRec, wrongSSPReq := suite.authedRequest(
		http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/promote-to-poam", wrongSSPID, created.ID),
		map[string]any{},
	)
	suite.server.E().ServeHTTP(wrongSSPRec, wrongSSPReq)
	require.Equal(suite.T(), http.StatusNotFound, wrongSSPRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_WithRemediationTemplate() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Risk with remediation template",
		"description": "Has a remediation template with tasks",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	// Create a remediation template with 2 tasks.
	// Note: the remediationTaskRequest uses "order-index" (kebab-case) as its JSON tag.
	remRec, remReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), map[string]any{
		"title": "Standard remediation plan",
		"tasks": []map[string]any{
			{"title": "Template task 1", "order-index": 1},
			{"title": "Template task 2", "order-index": 2},
		},
	})
	suite.server.E().ServeHTTP(remRec, remReq)
	require.Equal(suite.T(), http.StatusCreated, remRec.Code)

	// Accept the risk.
	acceptDeadline := time.Now().Add(14 * 24 * time.Hour).UTC()
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "accepted",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	// Promote with 1 extra milestone — should have 3 total (2 template + 1 extra).
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{
		"milestones": []map[string]any{
			{"title": "Extra milestone from request", "orderIndex": 2},
		},
	})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusCreated, promoteRec.Code)

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(promoteRec.Body.Bytes(), &poamResp))

	// Should have 3 milestones: 2 from template + 1 from request.
	require.Len(suite.T(), poamResp.Data.Milestones, 3)
	require.Equal(suite.T(), "Template task 1", poamResp.Data.Milestones[0].Title)
	require.Equal(suite.T(), "Template task 2", poamResp.Data.Milestones[1].Title)
	require.Equal(suite.T(), "Extra milestone from request", poamResp.Data.Milestones[2].Title)
}

// Ensure the testing import is used.
var _ = (*testing.T)(nil)
