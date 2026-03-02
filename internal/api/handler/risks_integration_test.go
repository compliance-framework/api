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
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, nil, nil, nil, nil)
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
		"sspId":       sspID,
		"status":      "open",
		"likelihood":  "medium",
		"impact":      "high",
	}

	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", createReq)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)
	require.Contains(suite.T(), rec.Body.String(), "\"evidenceIds\":[]")
	require.Contains(suite.T(), rec.Body.String(), "\"controlLinks\":[]")
	require.Contains(suite.T(), rec.Body.String(), "\"componentIds\":[]")
	require.Contains(suite.T(), rec.Body.String(), "\"subjectIds\":[]")

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))
	require.Equal(suite.T(), "open", created.Data.Status)
	require.Equal(suite.T(), "medium", *created.Data.Likelihood)

	secondReq := map[string]any{
		"title":       "Second risk",
		"description": "Secondary entry",
		"sspId":       sspID,
		"status":      "open",
	}
	secondRec, secondCall := suite.authedRequest(http.MethodPost, "/api/risks", secondReq)
	suite.server.E().ServeHTTP(secondRec, secondCall)
	require.Equal(suite.T(), http.StatusCreated, secondRec.Code)

	listRec, listReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks?status=open&sspId=%s&page=1&limit=1&sort=createdAt&order=asc", created.Data.SSPID.String()), nil)
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
		"sspId":       suite.newSSPID(),
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
		"status":                  "risk-accepted",
		"reviewDeadline":          time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"acceptanceJustification": "invalid after closed",
	})
	suite.server.E().ServeHTTP(acceptedAfterClosedRec, acceptedAfterClosedReq)
	require.Equal(suite.T(), http.StatusBadRequest, acceptedAfterClosedRec.Code)

	acceptedPath := suite.createRisk(map[string]any{
		"title":       "Accepted path",
		"description": "acceptance transition",
		"sspId":       suite.newSSPID(),
		"status":      "investigating",
	})

	deadline := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	acceptReq := map[string]any{
		"status":                  "risk-accepted",
		"reviewDeadline":          deadline,
		"reviewJustification":     "Quarterly governance review",
		"acceptanceJustification": "Business accepted",
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
		"sspId":       suite.newSSPID(),
	}
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", createReq)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))

	linkReq := map[string]any{"evidenceId": evidence.ID.String()}
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
		"title":          "Risk with link coverage",
		"description":    "cover controls/components/subjects",
		"sspId":          suite.newSSPID(),
		"reviewDeadline": reviewDeadline,
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "secops", "isPrimary": true},
		},
	}

	created := suite.createRisk(createReq)

	evidenceLinkReq := map[string]any{"evidenceId": evidence.ID.String()}
	evidenceLinkRec, evidenceLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), evidenceLinkReq)
	suite.server.E().ServeHTTP(evidenceLinkRec, evidenceLinkCall)
	require.Equal(suite.T(), http.StatusCreated, evidenceLinkRec.Code)

	controlLinkReq := map[string]any{"catalogId": catalogID.String(), "controlId": "AC-1"}
	controlLinkRec, controlLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), controlLinkReq)
	suite.server.E().ServeHTTP(controlLinkRec, controlLinkCall)
	require.Equal(suite.T(), http.StatusCreated, controlLinkRec.Code)

	componentLinkReq := map[string]any{"componentId": componentID.String()}
	componentLinkRec, componentLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/components", created.ID), componentLinkReq)
	suite.server.E().ServeHTTP(componentLinkRec, componentLinkCall)
	require.Equal(suite.T(), http.StatusCreated, componentLinkRec.Code)

	subjectLinkReq := map[string]any{"subjectId": subjectID.String()}
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

	filterByEvidenceRec, filterByEvidenceReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/risks?evidenceId=%s&page=1&limit=10", evidence.ID), nil)
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
		"sspId":       suite.newSSPID(),
	}

	invalidOwnerKind := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"sspId":       base["sspId"],
		"ownerAssignments": []map[string]any{
			{"ownerKind": "invalid", "ownerRef": "x", "isPrimary": true},
		},
	}
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", invalidOwnerKind)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	duplicateOwner := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"sspId":       base["sspId"],
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "dup", "isPrimary": false},
			{"ownerKind": "group", "ownerRef": "dup", "isPrimary": false},
		},
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", duplicateOwner)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	twoPrimaryOwners := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"sspId":       base["sspId"],
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "a", "isPrimary": true},
			{"ownerKind": "role", "ownerRef": "b", "isPrimary": true},
		},
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", twoPrimaryOwners)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	invalidUserRef := map[string]any{
		"title":       base["title"],
		"description": base["description"],
		"sspId":       base["sspId"],
		"ownerAssignments": []map[string]any{
			{"ownerKind": "user", "ownerRef": "not-a-uuid", "isPrimary": true},
		},
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", invalidUserRef)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	acceptedWithoutDeadline := map[string]any{
		"title":                   "Accepted missing deadline",
		"description":             "validation",
		"sspId":                   suite.newSSPID(),
		"status":                  "risk-accepted",
		"acceptanceJustification": "ok",
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", acceptedWithoutDeadline)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	acceptedWithoutJustification := map[string]any{
		"title":                   "Accepted missing justification",
		"description":             "validation",
		"sspId":                   suite.newSSPID(),
		"status":                  "risk-accepted",
		"reviewDeadline":          time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
		"acceptanceJustification": "",
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", acceptedWithoutJustification)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	acceptedWithPastDeadline := map[string]any{
		"title":                   "Accepted past deadline",
		"description":             "validation",
		"sspId":                   suite.newSSPID(),
		"status":                  "risk-accepted",
		"reviewDeadline":          time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
		"acceptanceJustification": "ok",
	}
	rec, req = suite.authedRequest(http.MethodPost, "/api/risks", acceptedWithPastDeadline)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	created := suite.createRisk(map[string]any{
		"title":       "Validation target risk",
		"description": "validation target",
		"sspId":       suite.newSSPID(),
	})

	badEvidenceReq, badEvidenceCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), map[string]any{})
	suite.server.E().ServeHTTP(badEvidenceReq, badEvidenceCall)
	require.Equal(suite.T(), http.StatusBadRequest, badEvidenceReq.Code)

	badControlReq, badControlCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), map[string]any{"catalogId": uuid.New().String()})
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
		"title":              "Create owner normalization",
		"description":        "primary owner should be canonical",
		"sspId":              suite.newSSPID(),
		"primaryOwnerUserId": primaryOwnerID.String(),
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "secops", "isPrimary": true},
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
		"sspId":       suite.newSSPID(),
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "secops", "isPrimary": true},
		},
	})

	primaryOwnerID := uuid.New()
	updateRec, updateReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"primaryOwnerUserId": primaryOwnerID.String(),
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
		"title":              "Update owner replacement preserves canonical primary owner",
		"description":        "ownerAssignments replacement should keep existing primaryOwnerUserId",
		"sspId":              suite.newSSPID(),
		"primaryOwnerUserId": primaryOwnerID.String(),
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "legacy", "isPrimary": true},
		},
	})

	updateRec, updateReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/risks/%s", created.ID), map[string]any{
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "new-group", "isPrimary": true},
			{"ownerKind": "role", "ownerRef": "security-reviewers", "isPrimary": false},
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
		"sspId":       suite.newSSPID(),
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "secops", "isPrimary": true},
			{"ownerKind": "role", "ownerRef": "security-reviewers", "isPrimary": false},
		},
	})

	evidenceLinkRec, evidenceLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), map[string]any{"evidenceId": evidence.ID.String()})
	suite.server.E().ServeHTTP(evidenceLinkRec, evidenceLinkCall)
	require.Equal(suite.T(), http.StatusCreated, evidenceLinkRec.Code)

	controlLinkRec, controlLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), map[string]any{
		"catalogId": catalogID.String(),
		"controlId": "AC-2",
	})
	suite.server.E().ServeHTTP(controlLinkRec, controlLinkCall)
	require.Equal(suite.T(), http.StatusCreated, controlLinkRec.Code)

	componentLinkRec, componentLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/components", created.ID), map[string]any{"componentId": componentID.String()})
	suite.server.E().ServeHTTP(componentLinkRec, componentLinkCall)
	require.Equal(suite.T(), http.StatusCreated, componentLinkRec.Code)

	subjectLinkRec, subjectLinkCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/subjects", created.ID), map[string]any{"subjectId": subjectID.String()})
	suite.server.E().ServeHTTP(subjectLinkRec, subjectLinkCall)
	require.Equal(suite.T(), http.StatusCreated, subjectLinkRec.Code)

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
}

func (suite *RiskApiIntegrationSuite) TestRiskNotFoundAndInvalidFilterBranches() {
	created := suite.createRisk(map[string]any{
		"title":       "NotFound target risk",
		"description": "target",
		"sspId":       suite.newSSPID(),
	})

	notFoundControlReq, notFoundControlCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/controls", created.ID), map[string]any{
		"catalogId": uuid.New().String(),
		"controlId": "AC-404",
	})
	suite.server.E().ServeHTTP(notFoundControlReq, notFoundControlCall)
	require.Equal(suite.T(), http.StatusNotFound, notFoundControlReq.Code)

	notFoundComponentReq, notFoundComponentCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/components", created.ID), map[string]any{
		"componentId": uuid.New().String(),
	})
	suite.server.E().ServeHTTP(notFoundComponentReq, notFoundComponentCall)
	require.Equal(suite.T(), http.StatusNotFound, notFoundComponentReq.Code)

	notFoundSubjectReq, notFoundSubjectCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/subjects", created.ID), map[string]any{
		"subjectId": uuid.New().String(),
	})
	suite.server.E().ServeHTTP(notFoundSubjectReq, notFoundSubjectCall)
	require.Equal(suite.T(), http.StatusNotFound, notFoundSubjectReq.Code)

	notFoundEvidenceReq, notFoundEvidenceCall := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/risks/%s/evidence", created.ID), map[string]any{
		"evidenceId": uuid.New().String(),
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
	createdLinkReq := map[string]any{"evidenceId": evidence.ID.String()}
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
}

func (suite *RiskApiIntegrationSuite) TestRiskListContextInternalErrorIs500() {
	created := suite.createRisk(map[string]any{
		"title":       "List context failure target",
		"description": "forces ensureRiskExists internal failure",
		"sspId":       suite.newSSPID(),
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
		"sspId":       suite.newSSPID(),
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
		"title":          "Optional field create",
		"description":    "exercise optional paths",
		"sspId":          suite.newSSPID(),
		"dedupeKey":      "scanner:ssp/control:ac-1",
		"firstSeenAt":    firstSeenAt.Format(time.RFC3339),
		"lastSeenAt":     lastSeenAt.Format(time.RFC3339),
		"reviewDeadline": reviewDeadline.Format(time.RFC3339),
		"lastReviewedAt": lastReviewedAt.Format(time.RFC3339),
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
		"sspId":       suite.newSSPID(),
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "legacy", "isPrimary": true},
		},
	})

	reviewedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	reviewDeadline := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)

	updateReq := map[string]any{
		"status":              "open",
		"title":               "Updated title",
		"description":         "Updated description",
		"likelihood":          "high",
		"impact":              "low",
		"reviewDeadline":      reviewDeadline.Format(time.RFC3339),
		"lastReviewedAt":      reviewedAt.Format(time.RFC3339),
		"reviewJustification": "Reviewed after compensating controls",
		"dedupeKey":           "updated:dedupe:key",
		"firstSeenAt":         time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339),
		"lastSeenAt":          time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339),
		"ownerAssignments": []map[string]any{
			{"ownerKind": "group", "ownerRef": "new-primary", "isPrimary": true},
			{"ownerKind": "role", "ownerRef": "security-reviewers", "isPrimary": false},
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
		"sspId":       suite.newSSPID(),
	}, "unknown-actor@example.com")
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusNotFound, createRec.Code)

	created := suite.createRisk(map[string]any{
		"title":       "Known actor create",
		"description": "used for update",
		"sspId":       suite.newSSPID(),
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
		"sspId":       uuid.New().String(),
	})
	suite.server.E().ServeHTTP(missingSSPRec, missingSSPReq)
	require.Equal(suite.T(), http.StatusNotFound, missingSSPRec.Code)

	created := suite.createRisk(map[string]any{
		"title":       "Break associations query",
		"description": "force an internal error path",
		"sspId":       suite.newSSPID(),
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

func (suite *RiskApiIntegrationSuite) createRisk(reqBody map[string]any) riskResponse {
	if rawSSPID, ok := reqBody["sspId"].(string); ok && rawSSPID != "" {
		suite.ensureSSPExists(rawSSPID)
	}
	rec, req := suite.authedRequest(http.MethodPost, "/api/risks", reqBody)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	var created GenericDataResponse[riskResponse]
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &created))
	return created.Data
}
