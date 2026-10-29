//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestEvidenceCreateLinks(t *testing.T) {
	suite.Run(t, new(EvidenceCreateLinksSuite))
}

// EvidenceCreateLinksSuite covers how EvidenceService.Create stores related entities:
// one multi-row insert per kind, one join-table insert per kind, and a column-only
// signature update. Its performance is measured by make bench-evidence-ingest.
type EvidenceCreateLinksSuite struct {
	tests.IntegrationTestSuite
}

func (suite *EvidenceCreateLinksSuite) TestCreateLinksAndSignsRelatedEntities() {
	suite.Require().NoError(suite.Migrator.Refresh())

	logger := zap.NewNop().Sugar()
	server := api.NewServer(context.Background(), logger, suite.Config, api.NewMetricsHandler(context.Background(), logger))
	evidenceService := evidencesvc.NewEvidenceService(suite.DB, logger, suite.Config, nil,
		evidencesvc.WithComponentDefinitionResolver(templates.NewSubjectTemplateService(suite.DB)))
	RegisterHandlers(server, logger, suite.DB, suite.Config, &APIServices{EvidenceService: evidenceService})

	agent, err := suite.CreateAgent("links-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "links-key")
	suite.Require().NoError(err)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	instance := "web-server/ec2/i-000001"
	body, err := json.Marshal(map[string]any{
		"uuid":   uuid.NewSHA1(uuid.NameSpaceURL, []byte(instance)),
		"title":  "IMDSv2 enforced",
		"start":  time.Now().Add(-time.Hour),
		"end":    time.Now().Add(-time.Minute),
		"labels": map[string]string{"_plugin": "links", "_policy": "p", "provider": "aws", "service": "ec2", "region": "eu-west-1", "account": "a"},
		"props":  []map[string]string{{"name": "imds", "value": "v2"}},
		"activities": []map[string]any{{"uuid": uuid.New(), "title": "Evaluate", "steps": []map[string]any{
			{"uuid": uuid.New(), "title": "Describe"}, {"uuid": uuid.New(), "title": "Evaluate"},
		}}},
		"components":      []map[string]any{{"identifier": "components/common/aws-ec2", "type": "service", "title": "EC2"}},
		"inventory-items": []map[string]any{{"identifier": instance, "type": "web-server", "implemented-components": []map[string]string{{"identifier": "components/common/aws-ec2"}}}},
		"subjects":        []map[string]any{{"identifier": instance, "type": "inventory-item"}},
		"status":          oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"},
	})
	suite.Require().NoError(err)

	// Twice: the second time every related row already exists and is only linked.
	for round := 0; round < 2; round++ {
		req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		rec := httptest.NewRecorder()
		server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

		// The response carries every linked entity...
		var created GenericDataResponse[CreatedEvidenceResponse]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &created))
		suite.Len(created.Data.Labels, 6, "round %d", round)
		suite.Len(created.Data.Components, 1, "round %d", round)
		suite.Len(created.Data.InventoryItems, 1, "round %d", round)
		suite.Len(created.Data.Activities, 1, "round %d", round)
		suite.Len(created.Data.Subjects, 1, "round %d", round)
		suite.Require().NotNil(created.Data.Signature, "round %d", round)

		// ...so does the stored evidence, with nested rows intact...
		stored, err := evidenceService.GetByID(*created.Data.ID)
		suite.Require().NoError(err)
		suite.Len(stored.Labels, 6)
		suite.Require().Len(stored.Activities, 1)
		suite.Len(stored.Activities[0].Steps, 2)
		suite.Require().Len(stored.InventoryItems, 1)
		suite.Len(stored.InventoryItems[0].ImplementedComponents, 1)
		suite.Len(stored.Components, 1)
		suite.Require().Len(stored.Subjects, 1)
		suite.Len(stored.Subjects[0].IncludeSubjects, 1)

		// ...and the signature, computed over what was stored, verifies.
		result, err := evidenceService.VerifyByID(*created.Data.ID)
		suite.Require().NoError(err)
		suite.True(result.IsValid, "round %d: %v", round, result.Errors)
	}
}
