//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/gorm/clause"
)

type RiskApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

func TestRiskAPI(t *testing.T) {
	suite.Run(t, new(RiskApiIntegrationSuite))
}

func (suite *RiskApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &APIServices{}
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, services)
}

func (suite *RiskApiIntegrationSuite) authedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	return suite.authedRequestWithToken(method, path, body, *token)
}

func (suite *RiskApiIntegrationSuite) authedRequestForEmail(method, path string, body any, email string) (*httptest.ResponseRecorder, *http.Request) {
	token, err := authn.GenerateJWTToken(&relational.User{Email: email, FirstName: "Unknown", LastName: "Actor"}, suite.Config.JWTPrivateKey)
	suite.Require().NoError(err)
	return suite.authedRequestWithToken(method, path, body, *token)
}

func (suite *RiskApiIntegrationSuite) authedRequestWithToken(method, path string, body any, token string) (*httptest.ResponseRecorder, *http.Request) {
	payload := []byte{}
	if body != nil {
		data, err := json.Marshal(body)
		suite.Require().NoError(err)
		payload = data
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	return rec, req
}

func (suite *RiskApiIntegrationSuite) ensureSSPExists(sspID string) {
	parsed, err := uuid.Parse(sspID)
	suite.Require().NoError(err)
	ssp := relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &parsed}}
	suite.Require().NoError(suite.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&ssp).Error)
}

func (suite *RiskApiIntegrationSuite) newSSPID() string {
	sspID := uuid.New().String()
	suite.ensureSSPExists(sspID)
	return sspID
}

func (suite *RiskApiIntegrationSuite) TestRiskCRUDAndFilter() {
	sspID := suite.newSSPID()
	createReq := map[string]any{
		"title":       "Undetected secrets committed to repository",
		"description": "Secrets may leak from source control",
		"ssp-id":      sspID,
		"status":      "open",
		"likelihood":  "medium",
		"impact":      "high",
	}

	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", createReq)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)
	require.Contains(suite.T(), rec.Body.String(), "\"evidence-ids\":[]")
	require.Contains(suite.T(), rec.Body.String(), "\"control-links\":[]")
	require.Contains(suite.T(), rec.Body.String(), "\"component-ids\":[]")
	require.Contains(suite.T(), rec.Body.String(), "\"subject-ids\":[]")

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))
	require.Equal(suite.T(), "open", created.Data.Status)
	require.Equal(suite.T(), "moderate", *created.Data.Likelihood)

	secondReq := map[string]any{
		"title":       "Second risk",
		"description": "Secondary entry",
		"ssp-id":      sspID,
		"status":      "open",
	}
	secondRec, secondCall := suite.authedRequest(http.MethodPost, "/api/risks", secondReq)
	suite.server.E().ServeHTTP(secondRec, secondCall)
	require.Equal(suite.T(), http.StatusCreated, secondRec.Code)

	listRec, listReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks?status=open&ssp-id=%s&page=1&limit=1&sort=created-at&order=asc", created.Data.SSPID.String()), nil)
	suite.server.E().ServeHTTP(listRec, listReq)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listResp struct {
		Data       []riskResponse `json:"data"`
		Total      int64          `json:"total"`
		Page       int            `json:"page"`
		Limit      int            `json:"limit"`
		TotalPages int            `json:"totalPages"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listResp))
	require.Len(suite.T(), listResp.Data, 1)
	require.Equal(suite.T(), int64(2), listResp.Total)
	require.Equal(suite.T(), 1, listResp.Page)
	require.Equal(suite.T(), 1, listResp.Limit)
	require.Equal(suite.T(), 2, listResp.TotalPages)

	getRec, getReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	deleteRec, deleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestRiskStatusTransitions() {
	createReq := map[string]any{
		"title":       "Transition risk",
		"description": "Transition testing",
		"ssp-id":      suite.newSSPID(),
		"status":      "open",
	}
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", createReq)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))

	invalidUpdate := map[string]any{"status": "risk-accepted"}
	invalidRec, invalidReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), invalidUpdate)
	suite.server.E().ServeHTTP(invalidRec, invalidReq)
	require.Equal(suite.T(), http.StatusBadRequest, invalidRec.Code)

	skippedTransitionRec, skippedTransitionReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), map[string]any{"status": "mitigating-planned"})
	suite.server.E().ServeHTTP(skippedTransitionRec, skippedTransitionReq)
	require.Equal(suite.T(), http.StatusBadRequest, skippedTransitionRec.Code)

	toInvestigating := map[string]any{"status": "investigating"}
	investigatingRec, investigatingReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), toInvestigating)
	suite.server.E().ServeHTTP(investigatingRec, investigatingReq)
	require.Equal(suite.T(), http.StatusOK, investigatingRec.Code)

	toPlannedRec, toPlannedReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), map[string]any{"status": "mitigating-planned"})
	suite.server.E().ServeHTTP(toPlannedRec, toPlannedReq)
	require.Equal(suite.T(), http.StatusOK, toPlannedRec.Code)

	toImplementedRec, toImplementedReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), map[string]any{"status": "mitigating-implemented"})
	suite.server.E().ServeHTTP(toImplementedRec, toImplementedReq)
	require.Equal(suite.T(), http.StatusOK, toImplementedRec.Code)

	toClosedRec, toClosedReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), map[string]any{"status": "closed"})
	suite.server.E().ServeHTTP(toClosedRec, toClosedReq)
	require.Equal(suite.T(), http.StatusOK, toClosedRec.Code)

	reopenRec, reopenReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), map[string]any{"status": "open"})
	suite.server.E().ServeHTTP(reopenRec, reopenReq)
	require.Equal(suite.T(), http.StatusBadRequest, reopenRec.Code)

	acceptedAfterClosedRec, acceptedAfterClosedReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.Data.ID), map[string]any{
		"status":                   "risk-accepted",
		"review-deadline":          time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"acceptance-justification": "invalid after closed",
	})
	suite.server.E().ServeHTTP(acceptedAfterClosedRec, acceptedAfterClosedReq)
	require.Equal(suite.T(), http.StatusBadRequest, acceptedAfterClosedRec.Code)

	acceptedPath := suite.createRisk(map[string]any{
		"title":       "Accepted path",
		"description": "acceptance transition",
		"ssp-id":      suite.newSSPID(),
		"status":      "investigating",
	})

	deadline := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	acceptReq := map[string]any{
		"status":                   "risk-accepted",
		"review-deadline":          deadline,
		"review-justification":     "Quarterly governance review",
		"acceptance-justification": "Business accepted",
	}
	acceptRec, acceptCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", acceptedPath.ID), acceptReq)
	suite.server.E().ServeHTTP(acceptRec, acceptCall)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	var events []riskrel.RiskEvent
	require.NoError(suite.T(), suite.DB.Where("risk_id = ?", acceptedPath.ID).Order("created_at asc").Find(&events).Error)

	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, e.EventType)
	}
	require.Contains(suite.T(), types, string(riskrel.RiskEventTypeCreated))
	require.Contains(suite.T(), types, string(riskrel.RiskEventTypeStatusChange))
	require.Contains(suite.T(), types, string(riskrel.RiskEventTypeAccepted))

	var reviews []riskrel.RiskReview
	require.NoError(suite.T(), suite.DB.Where("risk_id = ?", acceptedPath.ID).Order("created_at asc").Find(&reviews).Error)
	require.NotEmpty(suite.T(), reviews)
	require.NotNil(suite.T(), reviews[len(reviews)-1].ReviewJustification)
	require.Equal(suite.T(), "Quarterly governance review", *reviews[len(reviews)-1].ReviewJustification)
}

func (suite *RiskApiIntegrationSuite) TestRiskAcceptAndReviewEndpoints() {
	created := suite.createRisk(map[string]any{
		"title":       "Lifecycle risk",
		"description": "accept and review endpoints",
		"ssp-id":      suite.newSSPID(),
		"status":      "investigating",
	})

	missingJustificationRec, missingJustificationReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"review-deadline": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(missingJustificationRec, missingJustificationReq)
	require.Equal(suite.T(), http.StatusBadRequest, missingJustificationRec.Code)

	acceptDeadline := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "business accepted for a limited period",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	var accepted GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(acceptRec.Body.Bytes(), &accepted))
	require.Equal(suite.T(), "risk-accepted", accepted.Data.Status)
	require.NotNil(suite.T(), accepted.Data.AcceptanceJustification)
	require.Equal(suite.T(), "business accepted for a limited period", *accepted.Data.AcceptanceJustification)
	require.NotNil(suite.T(), accepted.Data.ReviewDeadline)
	require.WithinDuration(suite.T(), acceptDeadline, *accepted.Data.ReviewDeadline, time.Second)
	require.NotNil(suite.T(), accepted.Data.LastReviewedAt)

	reviewWithoutDeadlineRec, reviewWithoutDeadlineReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision": "extend",
	})
	suite.server.E().ServeHTTP(reviewWithoutDeadlineRec, reviewWithoutDeadlineReq)
	require.Equal(suite.T(), http.StatusBadRequest, reviewWithoutDeadlineRec.Code)

	reviewedAt := time.Now().Add(-90 * time.Minute).UTC().Truncate(time.Second)
	nextReviewDeadline := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	reviewExtendRec, reviewExtendReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"reviewed-at":          reviewedAt.Format(time.RFC3339),
		"decision":             "extend",
		"notes":                "controls are improving, keep accepted",
		"next-review-deadline": nextReviewDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(reviewExtendRec, reviewExtendReq)
	require.Equal(suite.T(), http.StatusOK, reviewExtendRec.Code)

	var extended GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(reviewExtendRec.Body.Bytes(), &extended))
	require.Equal(suite.T(), "risk-accepted", extended.Data.Status)
	require.NotNil(suite.T(), extended.Data.ReviewDeadline)
	require.WithinDuration(suite.T(), nextReviewDeadline, *extended.Data.ReviewDeadline, time.Second)
	require.NotNil(suite.T(), extended.Data.LastReviewedAt)
	require.WithinDuration(suite.T(), reviewedAt, *extended.Data.LastReviewedAt, time.Second)

	reviewReopenWithDeadlineRec, reviewReopenWithDeadlineReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision":             "reopen",
		"next-review-deadline": nextReviewDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(reviewReopenWithDeadlineRec, reviewReopenWithDeadlineReq)
	require.Equal(suite.T(), http.StatusBadRequest, reviewReopenWithDeadlineRec.Code)

	reviewReopenRec, reviewReopenReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision":   "reopen",
		"notes":      "mitigation can proceed now",
		"likelihood": "invalid-level",
		"impact":     "still-invalid",
	})
	suite.server.E().ServeHTTP(reviewReopenRec, reviewReopenReq)
	require.Equal(suite.T(), http.StatusOK, reviewReopenRec.Code)

	var reopened GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(reviewReopenRec.Body.Bytes(), &reopened))
	require.Equal(suite.T(), "investigating", reopened.Data.Status)
	require.Nil(suite.T(), reopened.Data.ReviewDeadline)
	require.NotNil(suite.T(), reopened.Data.LastReviewedAt)

	var reviews []riskrel.RiskReview
	require.NoError(suite.T(), suite.DB.Where("risk_id = ?", created.ID).Order("created_at asc").Find(&reviews).Error)
	require.Len(suite.T(), reviews, 2)
	require.Equal(suite.T(), "extend", reviews[0].Decision)
	require.Equal(suite.T(), "reopen", reviews[1].Decision)
	require.NotNil(suite.T(), reviews[0].ReviewJustification)
	require.Equal(suite.T(), "controls are improving, keep accepted", *reviews[0].ReviewJustification)

	var acceptedEvents int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypeAccepted)).
		Count(&acceptedEvents).Error)
	require.Equal(suite.T(), int64(1), acceptedEvents)

	var reviewedEvents int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypeReviewed)).
		Count(&reviewedEvents).Error)
	require.Equal(suite.T(), int64(2), reviewedEvents)
}

func (suite *RiskApiIntegrationSuite) TestRiskReassessReviewEndpoints() {
	created := suite.createRisk(map[string]any{
		"title":       "Reassess risk",
		"description": "reassess endpoint coverage",
		"ssp-id":      suite.newSSPID(),
		"status":      "open",
		"likelihood":  "low",
		"impact":      "low",
	})

	missingLikelihoodRec, missingLikelihoodReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision": "reassess",
		"impact":   "critical",
	})
	suite.server.E().ServeHTTP(missingLikelihoodRec, missingLikelihoodReq)
	require.Equal(suite.T(), http.StatusBadRequest, missingLikelihoodRec.Code)

	nextDeadline := time.Now().Add(14 * 24 * time.Hour).UTC().Truncate(time.Second)
	reassessWithDeadlineRec, reassessWithDeadlineReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision":             "reassess",
		"likelihood":           "medium",
		"impact":               "critical",
		"next-review-deadline": nextDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(reassessWithDeadlineRec, reassessWithDeadlineReq)
	require.Equal(suite.T(), http.StatusBadRequest, reassessWithDeadlineRec.Code)

	reassessRec, reassessReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision":   "reassess",
		"likelihood": "medium",
		"impact":     "critical",
		"notes":      "residual risk score increased",
	})
	suite.server.E().ServeHTTP(reassessRec, reassessReq)
	require.Equal(suite.T(), http.StatusOK, reassessRec.Code)

	var reassessed GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(reassessRec.Body.Bytes(), &reassessed))
	require.Equal(suite.T(), "open", reassessed.Data.Status)
	require.NotNil(suite.T(), reassessed.Data.Likelihood)
	require.NotNil(suite.T(), reassessed.Data.Impact)
	require.Equal(suite.T(), "moderate", *reassessed.Data.Likelihood)
	require.Equal(suite.T(), "critical", *reassessed.Data.Impact)
	require.NotNil(suite.T(), reassessed.Data.LastReviewedAt)

	var reviews []riskrel.RiskReview
	require.NoError(suite.T(), suite.DB.Where("risk_id = ?", created.ID).Order("created_at asc").Find(&reviews).Error)
	require.Len(suite.T(), reviews, 1)
	require.Equal(suite.T(), "reassess", reviews[0].Decision)
	require.NotNil(suite.T(), reviews[0].ReassessedLikelihood)
	require.NotNil(suite.T(), reviews[0].ReassessedImpact)
	require.Equal(suite.T(), "moderate", *reviews[0].ReassessedLikelihood)
	require.Equal(suite.T(), "critical", *reviews[0].ReassessedImpact)
	require.NotNil(suite.T(), reviews[0].ReviewJustification)
	require.Equal(suite.T(), "residual risk score increased", *reviews[0].ReviewJustification)

	var scoreReassessedEvents []riskrel.RiskEvent
	require.NoError(suite.T(), suite.DB.Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypeScoreReassessed)).Find(&scoreReassessedEvents).Error)
	require.Len(suite.T(), scoreReassessedEvents, 1)
	require.Equal(suite.T(), "reassess", scoreReassessedEvents[0].Payload["decision"])
	require.Equal(suite.T(), "open", scoreReassessedEvents[0].Payload["status"])
	require.Equal(suite.T(), "low", scoreReassessedEvents[0].Payload["fromLikelihood"])
	require.Equal(suite.T(), "low", scoreReassessedEvents[0].Payload["fromImpact"])
	require.Equal(suite.T(), "moderate", scoreReassessedEvents[0].Payload["toLikelihood"])
	require.Equal(suite.T(), "critical", scoreReassessedEvents[0].Payload["toImpact"])

	var reviewedEvents int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypeReviewed)).
		Count(&reviewedEvents).Error)
	require.Equal(suite.T(), int64(0), reviewedEvents)

	investigatingRisk := suite.createRisk(map[string]any{
		"title":       "Reassess investigating",
		"description": "status coverage",
		"ssp-id":      suite.newSSPID(),
		"status":      "investigating",
		"likelihood":  "low",
		"impact":      "low",
	})
	investigatingRec, investigatingReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", investigatingRisk.ID), map[string]any{
		"decision":   "reassess",
		"likelihood": "low",
		"impact":     "high",
	})
	suite.server.E().ServeHTTP(investigatingRec, investigatingReq)
	require.Equal(suite.T(), http.StatusOK, investigatingRec.Code)

	implementedRisk := suite.createRisk(map[string]any{
		"title":       "Reassess implemented",
		"description": "status coverage",
		"ssp-id":      suite.newSSPID(),
		"status":      "mitigating-implemented",
		"likelihood":  "low",
		"impact":      "low",
	})
	implementedRec, implementedReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", implementedRisk.ID), map[string]any{
		"decision":   "reassess",
		"likelihood": "low",
		"impact":     "high",
	})
	suite.server.E().ServeHTTP(implementedRec, implementedReq)
	require.Equal(suite.T(), http.StatusOK, implementedRec.Code)

	plannedRisk := suite.createRisk(map[string]any{
		"title":       "Reassess planned",
		"description": "status coverage",
		"ssp-id":      suite.newSSPID(),
		"status":      "mitigating-planned",
		"likelihood":  "low",
		"impact":      "low",
	})
	plannedRec, plannedReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", plannedRisk.ID), map[string]any{
		"decision":   "reassess",
		"likelihood": "low",
		"impact":     "high",
	})
	suite.server.E().ServeHTTP(plannedRec, plannedReq)
	require.Equal(suite.T(), http.StatusBadRequest, plannedRec.Code)

	accepted := suite.createRisk(map[string]any{
		"title":       "Reassess accepted",
		"description": "status coverage",
		"ssp-id":      suite.newSSPID(),
		"status":      "investigating",
	})
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", accepted.ID), map[string]any{
		"justification":   "temporary acceptance",
		"review-deadline": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	acceptedReassessRec, acceptedReassessReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", accepted.ID), map[string]any{
		"decision":   "reassess",
		"likelihood": "low",
		"impact":     "high",
	})
	suite.server.E().ServeHTTP(acceptedReassessRec, acceptedReassessReq)
	require.Equal(suite.T(), http.StatusBadRequest, acceptedReassessRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestSSPScopedRiskCRUD() {
	sspID := suite.newSSPID()
	otherSSPID := suite.newSSPID()

	createReq := map[string]any{
		"title":       "Scoped risk",
		"description": "created from scoped endpoint",
	}
	createRec, createHTTPReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks", sspID), createReq)
	suite.server.E().ServeHTTP(createRec, createHTTPReq)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.Equal(suite.T(), sspID, created.Data.SSPID.String())

	otherCreateRec, otherCreateReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks", otherSSPID), map[string]any{
		"title":       "Other scoped risk",
		"description": "should not appear in first scope list",
	})
	suite.server.E().ServeHTTP(otherCreateRec, otherCreateReq)
	require.Equal(suite.T(), http.StatusCreated, otherCreateRec.Code)

	listRec, listHTTPReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks?page=1&limit=20", sspID), nil)
	suite.server.E().ServeHTTP(listRec, listHTTPReq)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)
	var listResp struct {
		Data []riskResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listResp))
	require.Len(suite.T(), listResp.Data, 1)
	require.Equal(suite.T(), created.Data.ID, listResp.Data[0].ID)

	getRec, getReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s", sspID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	getOtherRec, getOtherReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s", otherSSPID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(getOtherRec, getOtherReq)
	require.Equal(suite.T(), http.StatusNotFound, getOtherRec.Code)

	updateScopedRec, updateScopedReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s", sspID, created.Data.ID), map[string]any{
		"title": "Scoped risk updated",
	})
	suite.server.E().ServeHTTP(updateScopedRec, updateScopedReq)
	require.Equal(suite.T(), http.StatusOK, updateScopedRec.Code)

	updateOtherRec, updateOtherReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s", otherSSPID, created.Data.ID), map[string]any{
		"title": "should fail",
	})
	suite.server.E().ServeHTTP(updateOtherRec, updateOtherReq)
	require.Equal(suite.T(), http.StatusNotFound, updateOtherRec.Code)

	deleteOtherRec, deleteOtherReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s", otherSSPID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteOtherRec, deleteOtherReq)
	require.Equal(suite.T(), http.StatusNotFound, deleteOtherRec.Code)

	deleteRec, deleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s", sspID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestSSPScopedRiskAcceptAndReviewEndpoints() {
	sspID := suite.newSSPID()
	otherSSPID := suite.newSSPID()

	createRec, createReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks", sspID), map[string]any{
		"title":       "Scoped lifecycle risk",
		"description": "accept/review scoped",
		"status":      "investigating",
	})
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))

	notFoundAcceptRec, notFoundAcceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/accept", otherSSPID, created.Data.ID), map[string]any{
		"justification":   "wrong scope",
		"review-deadline": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(notFoundAcceptRec, notFoundAcceptReq)
	require.Equal(suite.T(), http.StatusNotFound, notFoundAcceptRec.Code)

	acceptDeadline := time.Now().Add(14 * 24 * time.Hour).UTC().Truncate(time.Second)
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/accept", sspID, created.Data.ID), map[string]any{
		"justification":   "accepted scoped risk",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	var accepted GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(acceptRec.Body.Bytes(), &accepted))
	require.Equal(suite.T(), "risk-accepted", accepted.Data.Status)

	reviewDeadline := time.Now().Add(45 * 24 * time.Hour).UTC().Truncate(time.Second)
	reviewRec, reviewReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/review", sspID, created.Data.ID), map[string]any{
		"decision":             "extend",
		"notes":                "scoped extension",
		"next-review-deadline": reviewDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(reviewRec, reviewReq)
	require.Equal(suite.T(), http.StatusOK, reviewRec.Code)

	var reviewed GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(reviewRec.Body.Bytes(), &reviewed))
	require.Equal(suite.T(), "risk-accepted", reviewed.Data.Status)
	require.NotNil(suite.T(), reviewed.Data.ReviewDeadline)
	require.WithinDuration(suite.T(), reviewDeadline, *reviewed.Data.ReviewDeadline, time.Second)

	reopenWithDeadlineRec, reopenWithDeadlineReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/review", sspID, created.Data.ID), map[string]any{
		"decision":             "reopen",
		"next-review-deadline": reviewDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(reopenWithDeadlineRec, reopenWithDeadlineReq)
	require.Equal(suite.T(), http.StatusBadRequest, reopenWithDeadlineRec.Code)

	notFoundReviewRec, notFoundReviewReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/review", otherSSPID, created.Data.ID), map[string]any{
		"decision": "reopen",
	})
	suite.server.E().ServeHTTP(notFoundReviewRec, notFoundReviewReq)
	require.Equal(suite.T(), http.StatusNotFound, notFoundReviewRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestSSPScopedRiskReassessReviewEndpoint() {
	sspID := suite.newSSPID()
	otherSSPID := suite.newSSPID()

	createRec, createReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks", sspID), map[string]any{
		"title":       "Scoped reassess risk",
		"description": "scoped reassess coverage",
		"status":      "open",
		"likelihood":  "low",
		"impact":      "low",
	})
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))

	reviewRec, reviewReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/review", sspID, created.Data.ID), map[string]any{
		"decision":   "reassess",
		"likelihood": "medium",
		"impact":     "high",
		"notes":      "scoped reassessment",
	})
	suite.server.E().ServeHTTP(reviewRec, reviewReq)
	require.Equal(suite.T(), http.StatusOK, reviewRec.Code)

	var reassessed GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(reviewRec.Body.Bytes(), &reassessed))
	require.Equal(suite.T(), "open", reassessed.Data.Status)
	require.NotNil(suite.T(), reassessed.Data.Likelihood)
	require.Equal(suite.T(), "moderate", *reassessed.Data.Likelihood)
	require.NotNil(suite.T(), reassessed.Data.Impact)
	require.Equal(suite.T(), "high", *reassessed.Data.Impact)

	notFoundRec, notFoundReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/review", otherSSPID, created.Data.ID), map[string]any{
		"decision":   "reassess",
		"likelihood": "low",
		"impact":     "high",
	})
	suite.server.E().ServeHTTP(notFoundRec, notFoundReq)
	require.Equal(suite.T(), http.StatusNotFound, notFoundRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestRiskEventsAndReviewsEndpoints() {
	created := suite.createRisk(map[string]any{
		"title":       "History endpoints risk",
		"description": "events and reviews endpoint coverage",
		"ssp-id":      suite.newSSPID(),
		"status":      "investigating",
	})

	acceptDeadline := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/accept", created.ID), map[string]any{
		"justification":   "accepted for temporary period",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	extendDeadline := time.Now().Add(21 * 24 * time.Hour).UTC().Truncate(time.Second)
	reviewExtendRec, reviewExtendReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision":             "extend",
		"notes":                "controls partially implemented",
		"next-review-deadline": extendDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(reviewExtendRec, reviewExtendReq)
	require.Equal(suite.T(), http.StatusOK, reviewExtendRec.Code)

	reviewReopenRec, reviewReopenReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/review", created.ID), map[string]any{
		"decision": "reopen",
		"notes":    "further mitigation required",
	})
	suite.server.E().ServeHTTP(reviewReopenRec, reviewReopenReq)
	require.Equal(suite.T(), http.StatusOK, reviewReopenRec.Code)

	eventsRec, eventsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/events?page=1&limit=2", created.ID), nil)
	suite.server.E().ServeHTTP(eventsRec, eventsReq)
	require.Equal(suite.T(), http.StatusOK, eventsRec.Code)
	var eventsResp struct {
		Data       []riskrel.RiskEvent `json:"data"`
		Total      int64               `json:"total"`
		Page       int                 `json:"page"`
		Limit      int                 `json:"limit"`
		TotalPages int                 `json:"totalPages"`
	}
	require.NoError(suite.T(), json.Unmarshal(eventsRec.Body.Bytes(), &eventsResp))
	require.Len(suite.T(), eventsResp.Data, 2)
	require.GreaterOrEqual(suite.T(), eventsResp.Total, int64(5))
	require.Equal(suite.T(), 1, eventsResp.Page)
	require.Equal(suite.T(), 2, eventsResp.Limit)
	require.GreaterOrEqual(suite.T(), eventsResp.TotalPages, 3)
	require.NotEmpty(suite.T(), eventsResp.Data[0].EventType)
	require.NotNil(suite.T(), eventsResp.Data[0].Details)
	require.NotEmpty(suite.T(), *eventsResp.Data[0].Details)
	require.False(suite.T(), eventsResp.Data[0].CreatedAt.IsZero())
	require.False(suite.T(), eventsResp.Data[0].OccurredAt.IsZero())
	require.False(suite.T(), eventsResp.Data[0].OccurredAt.Before(eventsResp.Data[1].OccurredAt))

	reviewsRec, reviewsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/reviews?page=1&limit=1", created.ID), nil)
	suite.server.E().ServeHTTP(reviewsRec, reviewsReq)
	require.Equal(suite.T(), http.StatusOK, reviewsRec.Code)
	var reviewsResp struct {
		Data       []riskrel.RiskReview `json:"data"`
		Total      int64                `json:"total"`
		Page       int                  `json:"page"`
		Limit      int                  `json:"limit"`
		TotalPages int                  `json:"totalPages"`
	}
	require.NoError(suite.T(), json.Unmarshal(reviewsRec.Body.Bytes(), &reviewsResp))
	require.Len(suite.T(), reviewsResp.Data, 1)
	require.Equal(suite.T(), int64(2), reviewsResp.Total)
	require.Equal(suite.T(), 1, reviewsResp.Page)
	require.Equal(suite.T(), 1, reviewsResp.Limit)
	require.Equal(suite.T(), 2, reviewsResp.TotalPages)
	require.NotEmpty(suite.T(), reviewsResp.Data[0].Decision)
	require.False(suite.T(), reviewsResp.Data[0].CreatedAt.IsZero())
	require.False(suite.T(), reviewsResp.Data[0].ReviewedAt.IsZero())

	missingRiskID := uuid.New()
	missingEventsRec, missingEventsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/events?page=1&limit=20", missingRiskID), nil)
	suite.server.E().ServeHTTP(missingEventsRec, missingEventsReq)
	require.Equal(suite.T(), http.StatusNotFound, missingEventsRec.Code)
	require.Contains(suite.T(), strings.ToLower(missingEventsRec.Body.String()), "risk not found")

	missingReviewsRec, missingReviewsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/reviews?page=1&limit=20", missingRiskID), nil)
	suite.server.E().ServeHTTP(missingReviewsRec, missingReviewsReq)
	require.Equal(suite.T(), http.StatusNotFound, missingReviewsRec.Code)
	require.Contains(suite.T(), strings.ToLower(missingReviewsRec.Body.String()), "risk not found")

	emptyRiskID := uuid.New()
	require.NoError(suite.T(), suite.DB.Create(&riskrel.Risk{
		UUIDModel:   relational.UUIDModel{ID: &emptyRiskID},
		Title:       "no history rows",
		Description: "manually inserted risk for empty history assertions",
		Status:      string(riskrel.RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(riskrel.RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	emptyEventsRec, emptyEventsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/events?page=1&limit=20", emptyRiskID), nil)
	suite.server.E().ServeHTTP(emptyEventsRec, emptyEventsReq)
	require.Equal(suite.T(), http.StatusOK, emptyEventsRec.Code)
	var emptyEventsResp struct {
		Data  []riskrel.RiskEvent `json:"data"`
		Total int64               `json:"total"`
	}
	require.NoError(suite.T(), json.Unmarshal(emptyEventsRec.Body.Bytes(), &emptyEventsResp))
	require.Len(suite.T(), emptyEventsResp.Data, 0)
	require.Equal(suite.T(), int64(0), emptyEventsResp.Total)

	emptyReviewsRec, emptyReviewsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/reviews?page=1&limit=20", emptyRiskID), nil)
	suite.server.E().ServeHTTP(emptyReviewsRec, emptyReviewsReq)
	require.Equal(suite.T(), http.StatusOK, emptyReviewsRec.Code)
	var emptyReviewsResp struct {
		Data  []riskrel.RiskReview `json:"data"`
		Total int64                `json:"total"`
	}
	require.NoError(suite.T(), json.Unmarshal(emptyReviewsRec.Body.Bytes(), &emptyReviewsResp))
	require.Len(suite.T(), emptyReviewsResp.Data, 0)
	require.Equal(suite.T(), int64(0), emptyReviewsResp.Total)
}

func (suite *RiskApiIntegrationSuite) TestSSPScopedRiskEventsAndReviewsEndpoints() {
	sspID := suite.newSSPID()
	otherSSPID := suite.newSSPID()

	createRec, createReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks", sspID), map[string]any{
		"title":       "Scoped history risk",
		"description": "history endpoints scoped coverage",
		"status":      "investigating",
	})
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))

	acceptDeadline := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	acceptRec, acceptReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/accept", sspID, created.Data.ID), map[string]any{
		"justification":   "accepted in scoped context",
		"review-deadline": acceptDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(acceptRec, acceptReq)
	require.Equal(suite.T(), http.StatusOK, acceptRec.Code)

	nextDeadline := time.Now().Add(35 * 24 * time.Hour).UTC().Truncate(time.Second)
	reviewRec, reviewReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/review", sspID, created.Data.ID), map[string]any{
		"decision":             "extend",
		"notes":                "scoped review",
		"next-review-deadline": nextDeadline.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(reviewRec, reviewReq)
	require.Equal(suite.T(), http.StatusOK, reviewRec.Code)

	eventsRec, eventsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/events?page=1&limit=20", sspID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(eventsRec, eventsReq)
	require.Equal(suite.T(), http.StatusOK, eventsRec.Code)
	var eventsResp struct {
		Data []riskrel.RiskEvent `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(eventsRec.Body.Bytes(), &eventsResp))
	require.NotEmpty(suite.T(), eventsResp.Data)
	require.NotNil(suite.T(), eventsResp.Data[0].Details)
	require.NotEmpty(suite.T(), *eventsResp.Data[0].Details)

	reviewsRec, reviewsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/reviews?page=1&limit=20", sspID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(reviewsRec, reviewsReq)
	require.Equal(suite.T(), http.StatusOK, reviewsRec.Code)
	var reviewsResp struct {
		Data []riskrel.RiskReview `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(reviewsRec.Body.Bytes(), &reviewsResp))
	require.NotEmpty(suite.T(), reviewsResp.Data)

	notFoundEventsRec, notFoundEventsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/events?page=1&limit=20", otherSSPID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(notFoundEventsRec, notFoundEventsReq)
	require.Equal(suite.T(), http.StatusNotFound, notFoundEventsRec.Code)
	require.Contains(suite.T(), strings.ToLower(notFoundEventsRec.Body.String()), "risk not found")

	notFoundReviewsRec, notFoundReviewsReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/reviews?page=1&limit=20", otherSSPID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(notFoundReviewsRec, notFoundReviewsReq)
	require.Equal(suite.T(), http.StatusNotFound, notFoundReviewsRec.Code)
	require.Contains(suite.T(), strings.ToLower(notFoundReviewsRec.Body.String()), "risk not found")
}

func (suite *RiskApiIntegrationSuite) TestEvidenceLinksAreIdempotent() {
	evidence := relational.Evidence{
		UUID:        uuid.New(),
		Title:       "evidence",
		Description: "for risk",
		Start:       time.Now().Add(-2 * time.Hour),
		End:         time.Now().Add(-time.Hour),
	}
	require.NoError(suite.T(), suite.DB.Create(&evidence).Error)

	createReq := map[string]any{
		"title":       "Evidence linked risk",
		"description": "test",
		"ssp-id":      suite.newSSPID(),
	}
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", createReq)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))

	linkReq := map[string]any{"evidence-id": evidence.ID.String()}
	linkRec1, linkReq1 := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.Data.ID), linkReq)
	suite.server.E().ServeHTTP(linkRec1, linkReq1)
	require.Equal(suite.T(), http.StatusCreated, linkRec1.Code)

	linkRec2, linkReq2 := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.Data.ID), linkReq)
	suite.server.E().ServeHTTP(linkRec2, linkReq2)
	require.Equal(suite.T(), http.StatusCreated, linkRec2.Code)

	listRec, listReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/evidence?page=1&limit=20", created.Data.ID), nil)
	suite.server.E().ServeHTTP(listRec, listReq)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var links struct {
		Data []uuid.UUID `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &links))
	require.Len(suite.T(), links.Data, 1)

	var count int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvidenceLink{}).Where("risk_id = ?", created.Data.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)

	var evidenceEventCount int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.Data.ID, string(riskrel.RiskEventTypeEvidenceLink)).
		Count(&evidenceEventCount).Error)
	require.Equal(suite.T(), int64(1), evidenceEventCount)
}

func (suite *RiskApiIntegrationSuite) TestRiskControlComponentSubjectEndpointsAndFilters() {
	evidence := relational.Evidence{
		UUID:        uuid.New(),
		Title:       "evidence-for-links",
		Description: "for link coverage",
		Start:       time.Now().Add(-2 * time.Hour),
		End:         time.Now().Add(-time.Hour),
	}
	require.NoError(suite.T(), suite.DB.Create(&evidence).Error)

	catalogID := uuid.New()
	control := relational.Control{CatalogID: catalogID, ID: "AC-1", Title: "AC-1"}
	require.NoError(suite.T(), suite.DB.Create(&control).Error)

	componentID := uuid.New()
	component := relational.SystemComponent{
		UUIDModel:   relational.UUIDModel{ID: &componentID},
		Type:        "service",
		Title:       "component",
		Description: "desc",
		Purpose:     "purpose",
	}
	require.NoError(suite.T(), suite.DB.Create(&component).Error)

	subjectID := uuid.New()
	subjectSSPID := uuid.New()
	subject := relational.AssessmentSubject{
		UUIDModel: relational.UUIDModel{ID: &subjectID},
		Type:      "component",
		SSPID:     &subjectSSPID,
	}
	require.NoError(suite.T(), suite.DB.Create(&subject).Error)

	reviewDeadline := time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	createReq := map[string]any{
		"title":           "Risk with link coverage",
		"description":     "cover controls/components/subjects",
		"ssp-id":          suite.newSSPID(),
		"review-deadline": reviewDeadline,
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "secops", "is-primary": true},
		},
	}

	created := suite.createRisk(createReq)

	evidenceLinkReq := map[string]any{"evidence-id": evidence.ID.String()}
	evidenceLinkRec, evidenceLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), evidenceLinkReq)
	suite.server.E().ServeHTTP(evidenceLinkRec, evidenceLinkCall)
	require.Equal(suite.T(), http.StatusCreated, evidenceLinkRec.Code)

	controlLinkReq := map[string]any{"catalog-id": catalogID.String(), "control-id": "AC-1"}
	controlLinkRec, controlLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), controlLinkReq)
	suite.server.E().ServeHTTP(controlLinkRec, controlLinkCall)
	require.Equal(suite.T(), http.StatusCreated, controlLinkRec.Code)

	componentLinkReq := map[string]any{"component-id": componentID.String()}
	componentLinkRec, componentLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/components", created.ID), componentLinkReq)
	suite.server.E().ServeHTTP(componentLinkRec, componentLinkCall)
	require.Equal(suite.T(), http.StatusCreated, componentLinkRec.Code)

	subjectLinkReq := map[string]any{"subject-id": subjectID.String()}
	subjectLinkRec, subjectLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/subjects", created.ID), subjectLinkReq)
	suite.server.E().ServeHTTP(subjectLinkRec, subjectLinkCall)
	require.Equal(suite.T(), http.StatusCreated, subjectLinkRec.Code)

	var linkEventTypes []string
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).Where("risk_id = ?", created.ID).Pluck("event_type", &linkEventTypes).Error)
	require.Contains(suite.T(), linkEventTypes, string(riskrel.RiskEventTypeEvidenceLink))
	require.Contains(suite.T(), linkEventTypes, string(riskrel.RiskEventTypeControlLink))
	require.Contains(suite.T(), linkEventTypes, string(riskrel.RiskEventTypeComponentLink))
	require.Contains(suite.T(), linkEventTypes, string(riskrel.RiskEventTypeSubjectLink))

	controlListRec, controlListReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/controls?page=1&limit=20", created.ID), nil)
	suite.server.E().ServeHTTP(controlListRec, controlListReq)
	require.Equal(suite.T(), http.StatusOK, controlListRec.Code)
	var controlList struct {
		Data []riskrel.RiskControlLink `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(controlListRec.Body.Bytes(), &controlList))
	require.Len(suite.T(), controlList.Data, 1)
	require.Equal(suite.T(), "AC-1", controlList.Data[0].ControlID)

	componentListRec, componentListReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/components?page=1&limit=20", created.ID), nil)
	suite.server.E().ServeHTTP(componentListRec, componentListReq)
	require.Equal(suite.T(), http.StatusOK, componentListRec.Code)
	var componentList struct {
		Data []riskrel.RiskComponentLink `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(componentListRec.Body.Bytes(), &componentList))
	require.Len(suite.T(), componentList.Data, 1)
	require.Equal(suite.T(), componentID, componentList.Data[0].ComponentID)

	subjectListRec, subjectListReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/subjects?page=1&limit=20", created.ID), nil)
	suite.server.E().ServeHTTP(subjectListRec, subjectListReq)
	require.Equal(suite.T(), http.StatusOK, subjectListRec.Code)
	var subjectList struct {
		Data []riskrel.RiskSubjectLink `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(subjectListRec.Body.Bytes(), &subjectList))
	require.Len(suite.T(), subjectList.Data, 1)
	require.Equal(suite.T(), subjectID, subjectList.Data[0].SubjectID)

	filterByControlRec, filterByControlReq := suite.authedRequest(http.MethodGet, "/api/risks?controlId=AC-1&page=1&limit=10", nil)
	suite.server.E().ServeHTTP(filterByControlRec, filterByControlReq)
	require.Equal(suite.T(), http.StatusOK, filterByControlRec.Code)
	var controlFiltered struct {
		Data []riskResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(filterByControlRec.Body.Bytes(), &controlFiltered))
	require.NotEmpty(suite.T(), controlFiltered.Data)

	filterByEvidenceRec, filterByEvidenceReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks?evidenceId=%s&page=1&limit=10", evidence.UUID), nil)
	suite.server.E().ServeHTTP(filterByEvidenceRec, filterByEvidenceReq)
	require.Equal(suite.T(), http.StatusOK, filterByEvidenceRec.Code)

	filterByOwnerRec, filterByOwnerReq := suite.authedRequest(http.MethodGet, "/api/risks?ownerKind=group&ownerRef=secops&page=1&limit=10", nil)
	suite.server.E().ServeHTTP(filterByOwnerRec, filterByOwnerReq)
	require.Equal(suite.T(), http.StatusOK, filterByOwnerRec.Code)

	filterByDeadlineRec, filterByDeadlineReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks?reviewDeadlineBefore=%s&page=1&limit=10", url.QueryEscape(time.Now().Add(10*24*time.Hour).UTC().Format(time.RFC3339))), nil)
	suite.server.E().ServeHTTP(filterByDeadlineRec, filterByDeadlineReq)
	require.Equal(suite.T(), http.StatusOK, filterByDeadlineRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestRiskValidationAndBadRequestBranches() {
	base := map[string]any{
		"title":       "Validation risk",
		"description": "validation",
		"ssp-id":      suite.newSSPID(),
	}

	invalidOwnerKind := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"ssp-id":      base["ssp-id"],
		"owner-assignments": []map[string]any{
			{"owner-kind": "invalid", "owner-ref": "x", "is-primary": true},
		},
	}
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", invalidOwnerKind)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	duplicateOwner := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"ssp-id":      base["ssp-id"],
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "dup", "is-primary": false},
			{"owner-kind": "group", "owner-ref": "dup", "is-primary": false},
		},
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", duplicateOwner)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	twoPrimaryOwners := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"ssp-id":      base["ssp-id"],
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "a", "is-primary": true},
			{"owner-kind": "role", "owner-ref": "b", "is-primary": true},
		},
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", twoPrimaryOwners)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	invalidUserRef := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"ssp-id":      base["ssp-id"],
		"owner-assignments": []map[string]any{
			{"owner-kind": "user", "owner-ref": "not-a-uuid", "is-primary": true},
		},
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", invalidUserRef)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	acceptedWithoutDeadline := map[string]any{
		"title":                    "Accepted missing deadline",
		"description":              "validation",
		"ssp-id":                   suite.newSSPID(),
		"status":                   "risk-accepted",
		"acceptance-justification": "ok",
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", acceptedWithoutDeadline)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	acceptedWithoutJustification := map[string]any{
		"title":                    "Accepted missing justification",
		"description":              "validation",
		"ssp-id":                   suite.newSSPID(),
		"status":                   "risk-accepted",
		"review-deadline":          time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		"acceptance-justification": "",
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", acceptedWithoutJustification)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	acceptedWithPastDeadline := map[string]any{
		"title":                    "Accepted past deadline",
		"description":              "validation",
		"ssp-id":                   suite.newSSPID(),
		"status":                   "risk-accepted",
		"review-deadline":          time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
		"acceptance-justification": "ok",
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", acceptedWithPastDeadline)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	created := suite.createRisk(map[string]any{
		"title":       "Validation target risk",
		"description": "validation target",
		"ssp-id":      suite.newSSPID(),
	})

	badEvidenceReq, badEvidenceCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(badEvidenceReq, badEvidenceCall)
	require.Equal(suite.T(), http.StatusBadRequest, badEvidenceReq.Code)

	badControlReq, badControlCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), map[string]any{"catalog-id": uuid.New().String()})
	suite.server.E().ServeHTTP(badControlReq, badControlCall)
	require.Equal(suite.T(), http.StatusBadRequest, badControlReq.Code)

	badComponentReq, badComponentCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/components", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(badComponentReq, badComponentCall)
	require.Equal(suite.T(), http.StatusBadRequest, badComponentReq.Code)

	badSubjectReq, badSubjectCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/subjects", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(badSubjectReq, badSubjectCall)
	require.Equal(suite.T(), http.StatusBadRequest, badSubjectReq.Code)
}

func (suite *RiskApiIntegrationSuite) TestRiskCreatePrimaryOwnerUserIDNormalizesPrimaryAssignments() {
	primaryOwnerID := uuid.New()
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", map[string]any{
		"title":                 "Create owner normalization",
		"description":           "primary owner should be canonical",
		"ssp-id":                suite.newSSPID(),
		"primary-owner-user-id": primaryOwnerID.String(),
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "secops", "is-primary": true},
		},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotNil(suite.T(), created.Data.PrimaryOwnerUserID)
	require.Equal(suite.T(), primaryOwnerID, *created.Data.PrimaryOwnerUserID)

	var primaryCount int
	var groupAssignment *riskOwnerAssignmentResponse
	var userPrimary *riskOwnerAssignmentResponse
	for i := range created.Data.OwnerAssignments {
		assignment := &created.Data.OwnerAssignments[i]
		if assignment.OwnerKind == "group" && assignment.OwnerRef == "secops" {
			groupAssignment = assignment
		}
		if assignment.IsPrimary {
			primaryCount++
			if assignment.OwnerKind == "user" && assignment.OwnerRef == primaryOwnerID.String() {
				userPrimary = assignment
			}
		}
	}

	require.Equal(suite.T(), 1, primaryCount)
	require.NotNil(suite.T(), userPrimary)
	require.NotNil(suite.T(), groupAssignment)
	require.False(suite.T(), groupAssignment.IsPrimary)
}

func (suite *RiskApiIntegrationSuite) TestRiskUpdatePrimaryOwnerUserIDNormalizesExistingPrimaryAssignment() {
	created := suite.createRisk(map[string]any{
		"title":       "Update owner normalization",
		"description": "existing primary owner assignment should be demoted",
		"ssp-id":      suite.newSSPID(),
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "secops", "is-primary": true},
		},
	})

	primaryOwnerID := uuid.New()
	updateRec, updateReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"primary-owner-user-id": primaryOwnerID.String(),
	})
	suite.server.E().ServeHTTP(updateRec, updateReq)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.NotNil(suite.T(), updated.Data.PrimaryOwnerUserID)
	require.Equal(suite.T(), primaryOwnerID, *updated.Data.PrimaryOwnerUserID)

	var primaryCount int
	var groupAssignment *riskOwnerAssignmentResponse
	var userPrimary *riskOwnerAssignmentResponse
	for i := range updated.Data.OwnerAssignments {
		assignment := &updated.Data.OwnerAssignments[i]
		if assignment.OwnerKind == "group" && assignment.OwnerRef == "secops" {
			groupAssignment = assignment
		}
		if assignment.IsPrimary {
			primaryCount++
			if assignment.OwnerKind == "user" && assignment.OwnerRef == primaryOwnerID.String() {
				userPrimary = assignment
			}
		}
	}

	require.Equal(suite.T(), 1, primaryCount)
	require.NotNil(suite.T(), userPrimary)
	require.NotNil(suite.T(), groupAssignment)
	require.False(suite.T(), groupAssignment.IsPrimary)
}

func (suite *RiskApiIntegrationSuite) TestRiskUpdateReplacingOwnerAssignmentsPreservesExistingPrimaryOwnerUser() {
	primaryOwnerID := uuid.New()
	created := suite.createRisk(map[string]any{
		"title":                 "Update owner replacement preserves canonical primary owner",
		"description":           "ownerAssignments replacement should keep existing primaryOwnerUserId",
		"ssp-id":                suite.newSSPID(),
		"primary-owner-user-id": primaryOwnerID.String(),
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "legacy", "is-primary": true},
		},
	})

	updateRec, updateReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "new-group", "is-primary": true},
			{"owner-kind": "role", "owner-ref": "security-reviewers", "is-primary": false},
		},
	})
	suite.server.E().ServeHTTP(updateRec, updateReq)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.NotNil(suite.T(), updated.Data.PrimaryOwnerUserID)
	require.Equal(suite.T(), primaryOwnerID, *updated.Data.PrimaryOwnerUserID)

	var primaryCount int
	var primaryUserAssignment *riskOwnerAssignmentResponse
	var newGroupAssignment *riskOwnerAssignmentResponse
	var roleAssignment *riskOwnerAssignmentResponse
	for i := range updated.Data.OwnerAssignments {
		assignment := &updated.Data.OwnerAssignments[i]
		if assignment.IsPrimary {
			primaryCount++
		}
		if assignment.OwnerKind == "user" && assignment.OwnerRef == primaryOwnerID.String() {
			primaryUserAssignment = assignment
		}
		if assignment.OwnerKind == "group" && assignment.OwnerRef == "new-group" {
			newGroupAssignment = assignment
		}
		if assignment.OwnerKind == "role" && assignment.OwnerRef == "security-reviewers" {
			roleAssignment = assignment
		}
	}

	require.Equal(suite.T(), 1, primaryCount)
	require.NotNil(suite.T(), primaryUserAssignment)
	require.True(suite.T(), primaryUserAssignment.IsPrimary)
	require.NotNil(suite.T(), newGroupAssignment)
	require.False(suite.T(), newGroupAssignment.IsPrimary)
	require.NotNil(suite.T(), roleAssignment)
	require.False(suite.T(), roleAssignment.IsPrimary)
}

func (suite *RiskApiIntegrationSuite) TestRiskDeleteCleansLinkedSubResources() {
	evidence := relational.Evidence{
		UUID:        uuid.New(),
		Title:       "evidence-delete-cleanup",
		Description: "for risk delete cleanup",
		Start:       time.Now().Add(-2 * time.Hour),
		End:         time.Now().Add(-time.Hour),
	}
	require.NoError(suite.T(), suite.DB.Create(&evidence).Error)

	catalogID := uuid.New()
	control := relational.Control{CatalogID: catalogID, ID: "AC-2", Title: "AC-2"}
	require.NoError(suite.T(), suite.DB.Create(&control).Error)

	componentID := uuid.New()
	component := relational.SystemComponent{
		UUIDModel:   relational.UUIDModel{ID: &componentID},
		Type:        "service",
		Title:       "component-delete-cleanup",
		Description: "desc",
		Purpose:     "purpose",
	}
	require.NoError(suite.T(), suite.DB.Create(&component).Error)

	subjectID := uuid.New()
	subjectSSPID := uuid.New()
	subject := relational.AssessmentSubject{
		UUIDModel: relational.UUIDModel{ID: &subjectID},
		Type:      "component",
		SSPID:     &subjectSSPID,
	}
	require.NoError(suite.T(), suite.DB.Create(&subject).Error)

	created := suite.createRisk(map[string]any{
		"title":       "Delete link cleanup target",
		"description": "verify deletion of risk-owned sub resources",
		"ssp-id":      suite.newSSPID(),
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "secops", "is-primary": true},
			{"owner-kind": "role", "owner-ref": "security-reviewers", "is-primary": false},
		},
	})

	evidenceLinkRec, evidenceLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), map[string]any{"evidence-id": evidence.ID.String()})
	suite.server.E().ServeHTTP(evidenceLinkRec, evidenceLinkCall)
	require.Equal(suite.T(), http.StatusCreated, evidenceLinkRec.Code)

	controlLinkRec, controlLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), map[string]any{
		"catalog-id": catalogID.String(),
		"control-id": "AC-2",
	})
	suite.server.E().ServeHTTP(controlLinkRec, controlLinkCall)
	require.Equal(suite.T(), http.StatusCreated, controlLinkRec.Code)

	componentLinkRec, componentLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/components", created.ID), map[string]any{"component-id": componentID.String()})
	suite.server.E().ServeHTTP(componentLinkRec, componentLinkCall)
	require.Equal(suite.T(), http.StatusCreated, componentLinkRec.Code)

	subjectLinkRec, subjectLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/subjects", created.ID), map[string]any{"subject-id": subjectID.String()})
	suite.server.E().ServeHTTP(subjectLinkRec, subjectLinkCall)
	require.Equal(suite.T(), http.StatusCreated, subjectLinkRec.Code)
	threatCreateRec, threatCreateCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/threat-ids", created.ID), map[string]any{
		"system": "CWE",
		"id":     "22",
		"title":  "Path traversal",
	})
	suite.server.E().ServeHTTP(threatCreateRec, threatCreateCall)
	require.Equal(suite.T(), http.StatusCreated, threatCreateRec.Code)
	remCreateRec, remCreateCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), map[string]any{
		"title": "Delete cleanup remediation",
		"tasks": []map[string]any{
			{"title": "cleanup task", "order-index": 1},
		},
	})
	suite.server.E().ServeHTTP(remCreateRec, remCreateCall)
	require.Equal(suite.T(), http.StatusCreated, remCreateRec.Code)

	var count int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvidenceLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskControlLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskComponentLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskSubjectLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskOwnerAssignment{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(2), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskThreatRef{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskRemediationTemplate{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)
	require.NoError(suite.T(), suite.DB.Table("risk_remediation_tasks").Where("risk_remediation_template_id IN (SELECT id FROM risk_remediation_templates WHERE risk_id = ?)", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(1), count)

	deleteRec, deleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)

	getAfterDeleteRec, getAfterDeleteReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(getAfterDeleteRec, getAfterDeleteReq)
	require.Equal(suite.T(), http.StatusNotFound, getAfterDeleteRec.Code)

	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvidenceLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskControlLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskComponentLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskSubjectLink{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskOwnerAssignment{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskThreatRef{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskRemediationTemplate{}).Where("risk_id = ?", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
	require.NoError(suite.T(), suite.DB.Table("risk_remediation_tasks").Where("risk_remediation_template_id IN (SELECT id FROM risk_remediation_templates WHERE risk_id = ?)", created.ID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
}

func (suite *RiskApiIntegrationSuite) TestRiskNotFoundAndInvalidFilterBranches() {
	created := suite.createRisk(map[string]any{
		"title":       "NotFound target risk",
		"description": "target",
		"ssp-id":      suite.newSSPID(),
	})

	notFoundControlReq, notFoundControlCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), map[string]any{
		"catalog-id": uuid.New().String(),
		"control-id": "AC-404",
	})
	suite.server.E().ServeHTTP(notFoundControlReq, notFoundControlCall)
	require.Equal(suite.T(), http.StatusNotFound, notFoundControlReq.Code)

	notFoundComponentReq, notFoundComponentCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/components", created.ID), map[string]any{
		"component-id": uuid.New().String(),
	})
	suite.server.E().ServeHTTP(notFoundComponentReq, notFoundComponentCall)
	require.Equal(suite.T(), http.StatusNotFound, notFoundComponentReq.Code)

	notFoundSubjectReq, notFoundSubjectCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/subjects", created.ID), map[string]any{
		"subject-id": uuid.New().String(),
	})
	suite.server.E().ServeHTTP(notFoundSubjectReq, notFoundSubjectCall)
	require.Equal(suite.T(), http.StatusNotFound, notFoundSubjectReq.Code)

	notFoundEvidenceReq, notFoundEvidenceCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), map[string]any{
		"evidence-id": uuid.New().String(),
	})
	suite.server.E().ServeHTTP(notFoundEvidenceReq, notFoundEvidenceCall)
	require.Equal(suite.T(), http.StatusNotFound, notFoundEvidenceReq.Code)

	missingRiskID := uuid.New()
	getControlsMissingRiskRec, getControlsMissingRiskReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/controls?page=1&limit=20", missingRiskID), nil)
	suite.server.E().ServeHTTP(getControlsMissingRiskRec, getControlsMissingRiskReq)
	require.Equal(suite.T(), http.StatusNotFound, getControlsMissingRiskRec.Code)

	getComponentsMissingRiskRec, getComponentsMissingRiskReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/components?page=1&limit=20", missingRiskID), nil)
	suite.server.E().ServeHTTP(getComponentsMissingRiskRec, getComponentsMissingRiskReq)
	require.Equal(suite.T(), http.StatusNotFound, getComponentsMissingRiskRec.Code)

	getSubjectsMissingRiskRec, getSubjectsMissingRiskReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/subjects?page=1&limit=20", missingRiskID), nil)
	suite.server.E().ServeHTTP(getSubjectsMissingRiskRec, getSubjectsMissingRiskReq)
	require.Equal(suite.T(), http.StatusNotFound, getSubjectsMissingRiskRec.Code)

	evidence := relational.Evidence{
		UUID:        uuid.New(),
		Title:       "delete-link-evidence",
		Description: "for delete",
		Start:       time.Now().Add(-2 * time.Hour),
		End:         time.Now().Add(-time.Hour),
	}
	require.NoError(suite.T(), suite.DB.Create(&evidence).Error)
	createdLinkReq := map[string]any{"evidence-id": evidence.ID.String()}
	linkRec, linkReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), createdLinkReq)
	suite.server.E().ServeHTTP(linkRec, linkReq)
	require.Equal(suite.T(), http.StatusCreated, linkRec.Code)

	deleteRec, deleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s/evidence/%s", created.ID, evidence.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)

	var unlinkEvents int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypeEvidenceUnlink)).
		Count(&unlinkEvents).Error)
	require.Equal(suite.T(), int64(1), unlinkEvents)

	deleteAgainRec, deleteAgainReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s/evidence/%s", created.ID, evidence.ID), nil)
	suite.server.E().ServeHTTP(deleteAgainRec, deleteAgainReq)
	require.Equal(suite.T(), http.StatusNotFound, deleteAgainRec.Code)

	invalidPathRec, invalidPathReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s/evidence/not-a-uuid", created.ID), nil)
	suite.server.E().ServeHTTP(invalidPathRec, invalidPathReq)
	require.Equal(suite.T(), http.StatusBadRequest, invalidPathRec.Code)

	invalidSSPFilterRec, invalidSSPFilterReq := suite.authedRequest(http.MethodGet, "/api/risks?sspId=not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidSSPFilterRec, invalidSSPFilterReq)
	require.Equal(suite.T(), http.StatusBadRequest, invalidSSPFilterRec.Code)

	invalidEvidenceFilterRec, invalidEvidenceFilterReq := suite.authedRequest(http.MethodGet, "/api/risks?evidenceId=not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidEvidenceFilterRec, invalidEvidenceFilterReq)
	require.Equal(suite.T(), http.StatusBadRequest, invalidEvidenceFilterRec.Code)

	invalidDeadlineFilterRec, invalidDeadlineFilterReq := suite.authedRequest(http.MethodGet, "/api/risks?reviewDeadlineBefore=not-a-time", nil)
	suite.server.E().ServeHTTP(invalidDeadlineFilterRec, invalidDeadlineFilterReq)
	require.Equal(suite.T(), http.StatusBadRequest, invalidDeadlineFilterRec.Code)

	whitespaceLikelihoodRec, whitespaceLikelihoodReq := suite.authedRequest(http.MethodGet, "/api/risks?likelihood=%20", nil)
	suite.server.E().ServeHTTP(whitespaceLikelihoodRec, whitespaceLikelihoodReq)
	require.Equal(suite.T(), http.StatusBadRequest, whitespaceLikelihoodRec.Code)

	whitespaceImpactRec, whitespaceImpactReq := suite.authedRequest(http.MethodGet, "/api/risks?impact=%20", nil)
	suite.server.E().ServeHTTP(whitespaceImpactRec, whitespaceImpactReq)
	require.Equal(suite.T(), http.StatusBadRequest, whitespaceImpactRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestRiskListContextInternalErrorIs500() {
	created := suite.createRisk(map[string]any{
		"title":       "List context failure target",
		"description": "forces ensureRiskExists internal failure",
		"ssp-id":      suite.newSSPID(),
	})

	require.NoError(suite.T(), suite.DB.Exec("DROP TABLE risk_register_risks").Error)

	rec, req := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/controls?page=1&limit=20", created.ID), nil)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusInternalServerError, rec.Code)

	body := rec.Body.String()
	require.Contains(suite.T(), body, "internal server error")
	require.False(suite.T(), strings.Contains(strings.ToLower(body), "risk_register_risks"))
	require.False(suite.T(), strings.Contains(strings.ToLower(body), "no such table"))
}

func (suite *RiskApiIntegrationSuite) TestRiskGetAndDeleteMeaningfulErrorBranches() {
	riskID := uuid.New()

	invalidGetRec, invalidGetReq := suite.authedRequest(http.MethodGet, "/api/risks/not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidGetRec, invalidGetReq)
	require.Equal(suite.T(), http.StatusBadRequest, invalidGetRec.Code)

	missingGetRec, missingGetReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", riskID), nil)
	suite.server.E().ServeHTTP(missingGetRec, missingGetReq)
	require.Equal(suite.T(), http.StatusNotFound, missingGetRec.Code)

	invalidDeleteRec, invalidDeleteReq := suite.authedRequest(http.MethodDelete, "/api/risks/not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidDeleteRec, invalidDeleteReq)
	require.Equal(suite.T(), http.StatusBadRequest, invalidDeleteRec.Code)

	missingDeleteRec, missingDeleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s", riskID), nil)
	suite.server.E().ServeHTTP(missingDeleteRec, missingDeleteReq)
	require.Equal(suite.T(), http.StatusNotFound, missingDeleteRec.Code)

	created := suite.createRisk(map[string]any{
		"title":       "Delete then verify",
		"description": "error branches",
		"ssp-id":      suite.newSSPID(),
	})

	deleteRec, deleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)

	getAfterDeleteRec, getAfterDeleteReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(getAfterDeleteRec, getAfterDeleteReq)
	require.Equal(suite.T(), http.StatusNotFound, getAfterDeleteRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestRiskCreateWithOptionalFieldsAndDefaultStatus() {
	firstSeenAt := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	lastSeenAt := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	localTZ := time.FixedZone("UTC-03", -3*60*60)
	reviewDeadline := time.Now().Add(14 * 24 * time.Hour).In(localTZ).Truncate(time.Second)
	lastReviewedAt := time.Now().Add(-2 * time.Hour).In(localTZ).Truncate(time.Second)

	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", map[string]any{
		"title":            "Optional field create",
		"description":      "exercise optional paths",
		"ssp-id":           suite.newSSPID(),
		"dedupe-key":       "scanner:ssp/control:ac-1",
		"first-seen-at":    firstSeenAt.Format(time.RFC3339),
		"last-seen-at":     lastSeenAt.Format(time.RFC3339),
		"review-deadline":  reviewDeadline.Format(time.RFC3339),
		"last-reviewed-at": lastReviewedAt.Format(time.RFC3339),
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))
	require.Equal(suite.T(), "open", created.Data.Status)
	require.Equal(suite.T(), "manual", created.Data.SourceType)
	require.Equal(suite.T(), "", created.Data.DedupeKey)
	require.False(suite.T(), created.Data.FirstSeenAt.Equal(firstSeenAt))
	require.False(suite.T(), created.Data.LastSeenAt.Equal(lastSeenAt))
	require.NotNil(suite.T(), created.Data.ReviewDeadline)
	require.WithinDuration(suite.T(), reviewDeadline.UTC(), *created.Data.ReviewDeadline, time.Second)
	require.NotNil(suite.T(), created.Data.LastReviewedAt)
	require.WithinDuration(suite.T(), lastReviewedAt.UTC(), *created.Data.LastReviewedAt, time.Second)
}

func (suite *RiskApiIntegrationSuite) TestRiskUpdateWithoutStatusTransitionRecordsReview() {
	created := suite.createRisk(map[string]any{
		"title":       "Update target",
		"description": "baseline",
		"ssp-id":      suite.newSSPID(),
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "legacy", "is-primary": true},
		},
	})

	reviewedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	reviewDeadline := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)

	updateReq := map[string]any{
		"status":               "open",
		"title":                "Updated title",
		"description":          "Updated description",
		"likelihood":           "high",
		"impact":               "low",
		"review-deadline":      reviewDeadline.Format(time.RFC3339),
		"last-reviewed-at":     reviewedAt.Format(time.RFC3339),
		"review-justification": "Reviewed after compensating controls",
		"dedupe-key":           "updated:dedupe:key",
		"first-seen-at":        time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339),
		"last-seen-at":         time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339),
		"owner-assignments": []map[string]any{
			{"owner-kind": "group", "owner-ref": "new-primary", "is-primary": true},
			{"owner-kind": "role", "owner-ref": "security-reviewers", "is-primary": false},
		},
	}

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), updateReq)
	suite.server.E().ServeHTTP(updateRec, updateCall)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.Equal(suite.T(), "Updated title", updated.Data.Title)
	require.Equal(suite.T(), "Updated description", updated.Data.Description)
	require.Equal(suite.T(), "open", updated.Data.Status)
	require.Equal(suite.T(), "", updated.Data.DedupeKey)
	require.Equal(suite.T(), "high", *updated.Data.Likelihood)
	require.Equal(suite.T(), "low", *updated.Data.Impact)
	require.WithinDuration(suite.T(), reviewedAt, *updated.Data.LastReviewedAt, time.Second)
	require.Len(suite.T(), updated.Data.OwnerAssignments, 2)
	ownerRefs := map[string]bool{}
	for _, owner := range updated.Data.OwnerAssignments {
		ownerRefs[owner.OwnerRef] = true
	}
	require.Contains(suite.T(), ownerRefs, "new-primary")
	require.Contains(suite.T(), ownerRefs, "security-reviewers")

	var statusEventCount int64
	require.NoError(suite.T(), suite.DB.Model(&riskrel.RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", created.ID, string(riskrel.RiskEventTypeStatusChange)).
		Count(&statusEventCount).Error)
	require.Equal(suite.T(), int64(0), statusEventCount)

	var reviewRows []riskrel.RiskReview
	require.NoError(suite.T(), suite.DB.Where("risk_id = ?", created.ID).Order("created_at asc").Find(&reviewRows).Error)
	require.NotEmpty(suite.T(), reviewRows)
	lastReview := reviewRows[len(reviewRows)-1]
	require.NotNil(suite.T(), lastReview.ReviewJustification)
	require.Equal(suite.T(), "Reviewed after compensating controls", *lastReview.ReviewJustification)
	require.NotEmpty(suite.T(), lastReview.RiskSnapshot)
}

func (suite *RiskApiIntegrationSuite) TestRiskActorNotFoundReturnsNotFound() {
	createRec, createReq := suite.authedRequestForEmail(http.MethodPost, "/api/risks", map[string]any{
		"title":       "Unknown actor create",
		"description": "should fail actor resolution",
		"ssp-id":      suite.newSSPID(),
	}, "unknown-actor@example.com")
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusNotFound, createRec.Code)

	created := suite.createRisk(map[string]any{
		"title":       "Known actor create",
		"description": "used for update",
		"ssp-id":      suite.newSSPID(),
	})

	updateRec, updateReq := suite.authedRequestForEmail(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"description": "attempted by unknown actor",
	}, "unknown-actor@example.com")
	suite.server.E().ServeHTTP(updateRec, updateReq)
	require.Equal(suite.T(), http.StatusNotFound, updateRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestRiskCreateMissingSSPAndSanitizedInternalError() {
	missingSSPRec, missingSSPReq := suite.authedRequest(http.MethodPost, "/api/risks", map[string]any{
		"title":       "Missing SSP",
		"description": "should fail",
		"ssp-id":      uuid.New().String(),
	})
	suite.server.E().ServeHTTP(missingSSPRec, missingSSPReq)
	require.Equal(suite.T(), http.StatusNotFound, missingSSPRec.Code)

	created := suite.createRisk(map[string]any{
		"title":       "Break associations query",
		"description": "force an internal error path",
		"ssp-id":      suite.newSSPID(),
	})

	require.NoError(suite.T(), suite.DB.Exec("DROP TABLE risk_evidence_links").Error)

	firstRec, firstReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s", created.ID), nil)
	suite.server.E().ServeHTTP(firstRec, firstReq)
	require.Equal(suite.T(), http.StatusInternalServerError, firstRec.Code)
	body := firstRec.Body.String()
	require.Contains(suite.T(), body, "internal server error")
	require.False(suite.T(), strings.Contains(strings.ToLower(body), "relation"))
	require.False(suite.T(), strings.Contains(strings.ToLower(body), "risk_evidence_links"))
}

func (suite *RiskApiIntegrationSuite) TestRiskThreatAndRemediationInlineAndNestedCRUD() {
	created := suite.createRisk(map[string]any{
		"title":       "Threat/remediation inline",
		"description": "created with associations",
		"ssp-id":      suite.newSSPID(),
		"threat-ids": []map[string]any{
			{"system": "CWE", "id": "79", "title": "XSS"},
		},
		"remediation-template": map[string]any{
			"title":       "Fix XSS",
			"description": "Encode output",
			"tasks": []map[string]any{
				{"title": "Patch templates", "order-index": 1},
			},
		},
	})
	require.Len(suite.T(), created.ThreatIDs, 1)
	require.NotNil(suite.T(), created.Remediation)
	require.Len(suite.T(), created.Remediation.Tasks, 1)

	// Omitted fields on update keep existing associations.
	updateKeepRec, updateKeepReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"title": "Threat/remediation inline updated",
	})
	suite.server.E().ServeHTTP(updateKeepRec, updateKeepReq)
	require.Equal(suite.T(), http.StatusOK, updateKeepRec.Code)
	var kept GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(updateKeepRec.Body.Bytes(), &kept))
	require.Len(suite.T(), kept.Data.ThreatIDs, 1)
	require.NotNil(suite.T(), kept.Data.Remediation)

	// threat-ids must be an array when present.
	updateNullThreatsRec, updateNullThreatsReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"threat-ids": nil,
	})
	suite.server.E().ServeHTTP(updateNullThreatsRec, updateNullThreatsReq)
	require.Equal(suite.T(), http.StatusBadRequest, updateNullThreatsRec.Code)

	// Explicit replace semantics: [] clears threats; null removes remediation.
	updateClearRec, updateClearReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"threat-ids":           []map[string]any{},
		"remediation-template": nil,
	})
	suite.server.E().ServeHTTP(updateClearRec, updateClearReq)
	require.Equal(suite.T(), http.StatusOK, updateClearRec.Code)
	var cleared GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(updateClearRec.Body.Bytes(), &cleared))
	require.Len(suite.T(), cleared.Data.ThreatIDs, 0)
	require.Nil(suite.T(), cleared.Data.Remediation)

	// Threat nested CRUD
	postThreatRec, postThreatReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/threat-ids", created.ID), map[string]any{
		"system": "CWE",
		"id":     "200",
		"title":  "Data exposure",
	})
	suite.server.E().ServeHTTP(postThreatRec, postThreatReq)
	require.Equal(suite.T(), http.StatusCreated, postThreatRec.Code)
	var createdThreat GenericDataResponse[threatIDResponse]
	require.NoError(suite.T(), json.Unmarshal(postThreatRec.Body.Bytes(), &createdThreat))

	getThreatRec, getThreatReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/threat-ids/%s", created.ID, createdThreat.Data.ID), nil)
	suite.server.E().ServeHTTP(getThreatRec, getThreatReq)
	require.Equal(suite.T(), http.StatusOK, getThreatRec.Code)

	listThreatRec, listThreatReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/threat-ids?page=1&limit=20", created.ID), nil)
	suite.server.E().ServeHTTP(listThreatRec, listThreatReq)
	require.Equal(suite.T(), http.StatusOK, listThreatRec.Code)
	var listedThreats struct {
		Data []threatIDResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listThreatRec.Body.Bytes(), &listedThreats))
	require.Len(suite.T(), listedThreats.Data, 1)

	updateThreatRec, updateThreatReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s/threat-ids/%s", created.ID, createdThreat.Data.ID), map[string]any{
		"system": "CWE",
		"id":     "200",
		"title":  "Data exposure updated",
	})
	suite.server.E().ServeHTTP(updateThreatRec, updateThreatReq)
	require.Equal(suite.T(), http.StatusOK, updateThreatRec.Code)

	secondThreatRec, secondThreatReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/threat-ids", created.ID), map[string]any{
		"system": "CWE",
		"id":     "89",
		"title":  "SQL injection",
	})
	suite.server.E().ServeHTTP(secondThreatRec, secondThreatReq)
	require.Equal(suite.T(), http.StatusCreated, secondThreatRec.Code)
	var secondThreat GenericDataResponse[threatIDResponse]
	require.NoError(suite.T(), json.Unmarshal(secondThreatRec.Body.Bytes(), &secondThreat))

	duplicateThreatRec, duplicateThreatReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s/threat-ids/%s", created.ID, secondThreat.Data.ID), map[string]any{
		"system": "CWE",
		"id":     "200",
		"title":  "Should fail duplicate",
	})
	suite.server.E().ServeHTTP(duplicateThreatRec, duplicateThreatReq)
	require.Equal(suite.T(), http.StatusBadRequest, duplicateThreatRec.Code)

	deleteThreatRec, deleteThreatReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s/threat-ids/%s", created.ID, createdThreat.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteThreatRec, deleteThreatReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteThreatRec.Code)
	deleteSecondThreatRec, deleteSecondThreatReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s/threat-ids/%s", created.ID, secondThreat.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteSecondThreatRec, deleteSecondThreatReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteSecondThreatRec.Code)

	// Remediation nested CRUD
	createRemRec, createRemReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), map[string]any{
		"title": "Fix exposure",
		"tasks": []map[string]any{
			{"title": "Harden outputs", "order-index": 1},
		},
	})
	suite.server.E().ServeHTTP(createRemRec, createRemReq)
	require.Equal(suite.T(), http.StatusCreated, createRemRec.Code)

	conflictRemRec, conflictRemReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), map[string]any{
		"title": "Duplicate remediation",
	})
	suite.server.E().ServeHTTP(conflictRemRec, conflictRemReq)
	require.Equal(suite.T(), http.StatusConflict, conflictRemRec.Code)

	upsertRemRec, upsertRemReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), map[string]any{
		"title": "Fix exposure updated",
		"tasks": []map[string]any{
			{"title": "Task 1", "order-index": 1},
			{"title": "Task 2", "order-index": 2},
		},
	})
	suite.server.E().ServeHTTP(upsertRemRec, upsertRemReq)
	require.Equal(suite.T(), http.StatusOK, upsertRemRec.Code)

	getRemRec, getRemReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), nil)
	suite.server.E().ServeHTTP(getRemRec, getRemReq)
	require.Equal(suite.T(), http.StatusOK, getRemRec.Code)
	var gotRemediation GenericDataResponse[remediationTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(getRemRec.Body.Bytes(), &gotRemediation))
	require.Len(suite.T(), gotRemediation.Data.Tasks, 2)

	deleteRemRec, deleteRemReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/risks/%s/remediation-template", created.ID), nil)
	suite.server.E().ServeHTTP(deleteRemRec, deleteRemReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteRemRec.Code)
}

func (suite *RiskApiIntegrationSuite) TestSSPScopedThreatAndRemediationEndpoints() {
	sspID := suite.newSSPID()
	otherSSPID := suite.newSSPID()

	createRec, createReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks", sspID), map[string]any{
		"title":       "Scoped threat/remediation",
		"description": "scoped endpoints",
	})
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)
	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))

	postThreatRec, postThreatReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/threat-ids", sspID, created.Data.ID), map[string]any{
		"system": "CWE",
		"id":     "89",
		"title":  "SQL injection",
	})
	suite.server.E().ServeHTTP(postThreatRec, postThreatReq)
	require.Equal(suite.T(), http.StatusCreated, postThreatRec.Code)

	notFoundThreatRec, notFoundThreatReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/threat-ids", otherSSPID, created.Data.ID), map[string]any{
		"system": "CWE",
		"id":     "89",
		"title":  "SQL injection",
	})
	suite.server.E().ServeHTTP(notFoundThreatRec, notFoundThreatReq)
	require.Equal(suite.T(), http.StatusNotFound, notFoundThreatRec.Code)

	upsertRemRec, upsertRemReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/remediation-template", sspID, created.Data.ID), map[string]any{
		"title": "Scoped remediation",
		"tasks": []map[string]any{
			{"title": "Scoped task", "order-index": 1},
		},
	})
	suite.server.E().ServeHTTP(upsertRemRec, upsertRemReq)
	require.Equal(suite.T(), http.StatusOK, upsertRemRec.Code)

	getRemRec, getRemReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/risks/%s/remediation-template", sspID, created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRemRec, getRemReq)
	require.Equal(suite.T(), http.StatusOK, getRemRec.Code)
}

func (suite *RiskApiIntegrationSuite) createRisk(reqBody map[string]any) riskResponse {
	if rawSSPID, ok := reqBody["ssp-id"].(string); ok && rawSSPID != "" {
		suite.ensureSSPExists(rawSSPID)
	}
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", reqBody)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))
	return created.Data
}
