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

// TestPromoteToPoam_HappyPath verifies the full happy-path: a risk in
// investigating status is promoted to a POAM item, the POAM fields are
// populated correctly, and the risk status advances to mitigating-planned.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_HappyPath() {
	sspID := suite.newSSPID()

	// Use a deterministic owner UUID so we can assert inheritance.
	ownerID := uuid.New()

	// Create a risk directly in investigating status with an explicit owner.
	created := suite.createRisk(map[string]any{
		"title":                "Unencrypted data at rest",
		"description":          "Sensitive data stored without encryption",
		"ssp-id":               sspID,
		"status":               "investigating",
		"likelihood":           "high",
		"impact":               "critical",
		"primary-owner-user-id": ownerID.String(),
	})

	// Promote to POAM with full payload.
	deadline := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{
		"title":            "Encrypt data at rest — remediation plan",
		"deadline":         deadline.Format(time.RFC3339),
		"resourceRequired": "3 engineer days",
		"milestones": []map[string]any{
			{"title": "Identify all unencrypted data stores", "orderIndex": 1},
			{"title": "Apply AES-256 encryption to all stores", "orderIndex": 2},
		},
	})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusCreated, promoteRec.Code, "promote-to-poam should return 201: %s", promoteRec.Body.String())

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
	// PrimaryOwnerUserID should be inherited from the risk's explicit owner.
	require.NotNil(suite.T(), poamResp.Data.PrimaryOwnerUserID)
	require.Equal(suite.T(), ownerID, *poamResp.Data.PrimaryOwnerUserID)
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

	// Verify risk status was transitioned to mitigating-planned.
	getRec, getReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)
	var riskResp GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(getRec.Body.Bytes(), &riskResp))
	require.Equal(suite.T(), "mitigating-planned", riskResp.Data.Status, "risk status should be mitigating-planned after promotion")
}

// TestPromoteToPoam_DefaultsFromRisk verifies that when no title/description
// are provided, the POAM item inherits them from the risk.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_DefaultsFromRisk() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Weak password policy",
		"description": "Password complexity rules not enforced",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	// Promote with empty body — title and description should default from risk.
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusCreated, promoteRec.Code, "promote-to-poam should return 201: %s", promoteRec.Body.String())

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(promoteRec.Body.Bytes(), &poamResp))

	// Title and description should default to the risk's values.
	require.Equal(suite.T(), "Weak password policy", poamResp.Data.Title)
	require.Equal(suite.T(), "Password complexity rules not enforced", poamResp.Data.Description)
	require.Equal(suite.T(), "open", poamResp.Data.Status)
	require.Equal(suite.T(), "risk-promotion", poamResp.Data.SourceType)
}

// TestPromoteToPoam_RejectsNonInvestigatingRisk verifies that only risks in
// investigating status can be promoted; open and risk-accepted are rejected.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_RejectsNonInvestigatingRisk() {
	sspID := suite.newSSPID()

	// Risk in "open" status — cannot be promoted.
	openRisk := suite.createRisk(map[string]any{
		"title":       "Open risk",
		"description": "Not yet under investigation",
		"ssp-id":      sspID,
		"status":      "open",
	})

	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", openRisk.ID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusUnprocessableEntity, promoteRec.Code, "should return 422 for open risk")

	// Risk in "risk-accepted" status — accepted risks are not remediated.
	acceptedRisk := suite.createRisk(map[string]any{
		"title":       "Accepted risk",
		"description": "Formally accepted, not being remediated",
		"ssp-id":      sspID,
		"status":      "investigating",
	})
	acceptDeadline := time.Now().Add(14 * 24 * time.Hour).UTC()
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", acceptedRisk.ID), map[string]any{
		"justification":   "accepted pending policy review",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	promoteRec2, promoteReq2 := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", acceptedRisk.ID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec2, promoteReq2)
	require.Equal(suite.T(), http.StatusUnprocessableEntity, promoteRec2.Code, "should return 422 for risk-accepted risk")
}

// TestPromoteToPoam_RejectsActivePoamAlreadyLinked verifies that a second
// promotion is rejected when an active (non-completed) POAM item already exists.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_RejectsActivePoamAlreadyLinked() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Duplicate promotion risk",
		"description": "Testing re-promotion guard",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	// First promotion should succeed.
	firstRec, firstReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(firstRec, firstReq)
	require.Equal(suite.T(), http.StatusCreated, firstRec.Code, "first promotion should succeed: %s", firstRec.Body.String())

	// Second promotion should fail — active POAM item already linked.
	// Risk is now mitigating-planned, which is also not investigating, so we
	// expect 422 from the status guard.
	secondRec, secondReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(secondRec, secondReq)
	require.Equal(suite.T(), http.StatusUnprocessableEntity, secondRec.Code, "should return 422 when active POAM already linked")
}

// TestPromoteToPoam_RejectsNotFound verifies that promoting a non-existent
// risk returns 404.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_RejectsNotFound() {
	nonExistentID := uuid.New()
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", nonExistentID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusNotFound, promoteRec.Code)
}

// TestPromoteToPoam_SSPScoped_HappyPath verifies the SSP-scoped endpoint
// returns 201 with correct data for a risk belonging to the given SSP.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_SSPScoped_HappyPath() {
	sspID := suite.newSSPID()

	// Use a deterministic owner UUID so we can assert inheritance.
	sspOwnerID := uuid.New()

	created := suite.createRisk(map[string]any{
		"title":                "SSP-scoped promotion risk",
		"description":          "Testing SSP-scoped promote endpoint",
		"ssp-id":               sspID,
		"status":               "investigating",
		"primary-owner-user-id": sspOwnerID.String(),
	})

	// Promote via SSP-scoped endpoint.
	sspPromoteRec, sspPromoteReq := suite.authedRequest(
		http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/promote-to-poam", sspID, created.ID),
		map[string]any{},
	)
	suite.server.E().ServeHTTP(sspPromoteRec, sspPromoteReq)
	require.Equal(suite.T(), http.StatusCreated, sspPromoteRec.Code, "SSP-scoped promote should return 201: %s", sspPromoteRec.Body.String())

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(sspPromoteRec.Body.Bytes(), &poamResp))
	require.Equal(suite.T(), "SSP-scoped promotion risk", poamResp.Data.Title)
	// PrimaryOwnerUserID should be inherited from the risk's explicit owner.
	require.NotNil(suite.T(), poamResp.Data.PrimaryOwnerUserID)
	require.Equal(suite.T(), sspOwnerID, *poamResp.Data.PrimaryOwnerUserID)
}

// TestPromoteToPoam_SSPScoped_RejectsWrongSSP verifies that promoting via a
// different SSP's scoped endpoint returns 404.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_SSPScoped_RejectsWrongSSP() {
	sspID := suite.newSSPID()
	wrongSSPID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Wrong SSP risk",
		"description": "Risk belongs to a different SSP",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	// Attempt to promote via wrong SSP — should return 404.
	wrongSSPRec, wrongSSPReq := suite.authedRequest(
		http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/promote-to-poam", wrongSSPID, created.ID),
		map[string]any{},
	)
	suite.server.E().ServeHTTP(wrongSSPRec, wrongSSPReq)
	require.Equal(suite.T(), http.StatusNotFound, wrongSSPRec.Code)
}

// TestPromoteToPoam_WithRemediationTemplate verifies that milestones from the
// risk's RemediationTemplate are copied first, followed by any extra milestones
// from the request body.
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_WithRemediationTemplate() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Risk with remediation template",
		"description": "Has a remediation template with tasks",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	// Create a remediation template with 2 tasks.
	// Note: remediationTaskRequest uses "order-index" (kebab-case) as its JSON tag.
	remRec, remReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), map[string]any{
		"title": "Standard remediation plan",
		"tasks": []map[string]any{
			{"title": "Template task 1", "order-index": 1},
			{"title": "Template task 2", "order-index": 2},
		},
	})
	suite.server.E().ServeHTTP(remRec, remReq)
	require.Equal(suite.T(), http.StatusCreated, remRec.Code, "remediation template creation should return 201: %s", remRec.Body.String())

	// Promote with 1 extra milestone — should have 3 total (2 template + 1 extra).
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{
		"milestones": []map[string]any{
			{"title": "Extra milestone from request", "orderIndex": 3},
		},
	})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusCreated, promoteRec.Code, "promote-to-poam should return 201: %s", promoteRec.Body.String())

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(promoteRec.Body.Bytes(), &poamResp))

	// Should have 3 milestones: 2 from template + 1 from request.
	require.Len(suite.T(), poamResp.Data.Milestones, 3)
	require.Equal(suite.T(), "Template task 1", poamResp.Data.Milestones[0].Title)
	require.Equal(suite.T(), "Template task 2", poamResp.Data.Milestones[1].Title)
	require.Equal(suite.T(), "Extra milestone from request", poamResp.Data.Milestones[2].Title)
}

// TestPromoteToPoam_CompletionAdvancesRiskStatus verifies the full lifecycle:
// promote (investigating → mitigating-planned), then complete the POAM item
// (mitigating-planned → mitigating-implemented).
func (suite *RiskApiIntegrationSuite) TestPromoteToPoam_CompletionAdvancesRiskStatus() {
	sspID := suite.newSSPID()

	created := suite.createRisk(map[string]any{
		"title":       "Lifecycle risk",
		"description": "Testing full POAM lifecycle",
		"ssp-id":      sspID,
		"status":      "investigating",
	})

	// Promote to POAM.
	promoteRec, promoteReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/promote-to-poam", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(promoteRec, promoteReq)
	require.Equal(suite.T(), http.StatusCreated, promoteRec.Code, "promote should succeed: %s", promoteRec.Body.String())

	var poamResp GenericDataResponse[poamItemResponse]
	require.NoError(suite.T(), json.Unmarshal(promoteRec.Body.Bytes(), &poamResp))
	poamID := poamResp.Data.ID

	// Verify risk is now mitigating-planned.
	getRec, getReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)
	var riskResp GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(getRec.Body.Bytes(), &riskResp))
	require.Equal(suite.T(), "mitigating-planned", riskResp.Data.Status)

	// Complete the POAM item.
	completeRec, completeReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/poam-items/%s", poamID), map[string]any{
		"status": "completed",
	})
	suite.server.E().ServeHTTP(completeRec, completeReq)
	require.Equal(suite.T(), http.StatusOK, completeRec.Code, "POAM completion should succeed: %s", completeRec.Body.String())

	// Verify risk has advanced to mitigating-implemented.
	getRec2, getReq2 := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(getRec2, getReq2)
	require.Equal(suite.T(), http.StatusOK, getRec2.Code)
	var riskResp2 GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(getRec2.Body.Bytes(), &riskResp2))
	require.Equal(suite.T(), "mitigating-implemented", riskResp2.Data.Status, "risk should advance to mitigating-implemented after POAM completion")

	// Verify poam_completed event was emitted on the risk.
	var completedEvents int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypePoamCompleted)).
		Count(&completedEvents).Error)
	require.Equal(suite.T(), int64(1), completedEvents)
}

// Ensure the testing import is used.
var _ = (*testing.T)(nil)
