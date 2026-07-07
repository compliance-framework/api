//go:build integration

package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// SSPExportOfferingAuthzIntegrationSuite exercises the ssp:export / ssp-export-offering:read
// gates through a real cedar-driven PEP (not the nil-pep-builds-builtin path every other oscal
// integration test uses, which allows every authenticated request regardless of role and so
// never actually proves role-based enforcement).
type SSPExportOfferingAuthzIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestSSPExportOfferingAuthzIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SSPExportOfferingAuthzIntegrationSuite))
}

// newCedarServer builds a server whose PEP is backed by the real embedded Cedar PDP (roles
// resolved from the ccf_role_assignments table), instead of the nil-pep/builtin-driver path.
func (suite *SSPExportOfferingAuthzIntegrationSuite) newCedarServer() *api.Server {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	pdp, err := authz.Open(authz.Options{Driver: authz.DriverCedar}, authz.Deps{
		DB:     suite.DB,
		Config: suite.Config,
		Logger: logger.Sugar(),
	})
	suite.Require().NoError(err)
	pep := middleware.NewPEP(pdp, authz.FailClosed, logger.Sugar())

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil, pep)
	return server
}

// createRoledUser creates a user row and grants it roleName via a direct ccf_role_assignments
// insert (the table the DB-backed role resolver reads; bypasses the admin HTTP route, which is
// unnecessary indirection for seeding test fixtures), then mints a JWT for that specific user.
func (suite *SSPExportOfferingAuthzIntegrationSuite) createRoledUser(email, roleName string) string {
	user := relational.User{Email: email, FirstName: "Test", LastName: "User"}
	suite.Require().NoError(suite.DB.Create(&user).Error)

	suite.Require().NoError(suite.DB.Create(&relational.CCFRoleAssignment{
		RoleName:     roleName,
		AssigneeType: relational.RoleAssigneeTypeUser,
		AssigneeID:   relational.NormalizeAssigneeID(email),
	}).Error)

	token, err := authn.GenerateJWTToken(&user, suite.Config.JWTPrivateKey)
	suite.Require().NoError(err)
	return *token
}

func (suite *SSPExportOfferingAuthzIntegrationSuite) authedRequest(server *api.Server, method, path, token string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		suite.Require().NoError(err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	rec := httptest.NewRecorder()
	server.E().ServeHTTP(rec, req)
	return rec
}

func minimalSSP(componentUUID string) *oscalTypes_1_1_3.SystemSecurityPlan {
	now := time.Now()
	return &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: uuid.New().String(),
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Export Offering AuthZ Test SSP",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{Href: "https://example.com/profiles/test"},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName:               "Test System",
			Description:              "Test system for export-offering authz",
			SecuritySensitivityLevel: "low",
			SystemIds: []oscalTypes_1_1_3.SystemId{
				{IdentifierType: "https://ietf.org/rfc/rfc4122", ID: uuid.New().String()},
			},
			Status: oscalTypes_1_1_3.Status{State: "operational"},
			SystemInformation: oscalTypes_1_1_3.SystemInformation{
				InformationTypes: []oscalTypes_1_1_3.InformationType{
					{UUID: uuid.New().String(), Title: "Test Info", Description: "Test info type"},
				},
			},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Components: []oscalTypes_1_1_3.SystemComponent{
				{
					UUID:        componentUUID,
					Type:        "software",
					Title:       "Test Component",
					Description: "Test component",
					Status:      oscalTypes_1_1_3.SystemComponentStatus{State: "operational"},
				},
			},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "Control implementation for export-offering authz test",
			ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
				{UUID: uuid.New().String(), ControlId: "ac-1"},
			},
		},
	}
}

// TestPublishRequiresSSPExportContributorCan_ViewerCannot is the ticket's authz AC:
// a contributor publishes an offering of 2 controls (1 per-statement); a viewer gets 403 on
// publish and 200 on read (via the top-level ssp-export-offering:read catalog).
func (suite *SSPExportOfferingAuthzIntegrationSuite) TestPublishRequiresSSPExportContributorCan_ViewerCannot() {
	suite.Require().NoError(suite.Migrator.Refresh())

	contributorToken := suite.createRoledUser("contributor@example.com", "contributor")
	viewerToken := suite.createRoledUser("viewer@example.com", "viewer")

	server := suite.newCedarServer()

	componentUUID := uuid.New().String()
	ssp := minimalSSP(componentUUID)
	rec := suite.authedRequest(server, "POST", "/api/oscal/system-security-plans", contributorToken, ssp)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// Create the offering as the contributor (ssp:export).
	rec = suite.authedRequest(server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings", ssp.UUID),
		contributorToken,
		map[string]string{"title": "Leverageable controls", "description": "AC-1 and a per-statement AC-2"},
	)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var created handler.GenericDataResponse[relational.SSPExportOffering]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &created))
	offeringID := created.Data.ID.String()

	// A viewer must not be able to curate items either — same ssp:export gate.
	stmtID := "ac-2_stmt.a"
	itemPath := fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/items", ssp.UUID, offeringID)
	rec = suite.authedRequest(server, "POST", itemPath, viewerToken, map[string]any{
		"controlId": "ac-1", "componentUuid": componentUUID, "providedUuid": uuid.New().String(),
	})
	suite.Require().Equal(http.StatusForbidden, rec.Code, rec.Body.String())

	// Contributor adds the 2 controls: one control-level, one per-statement.
	rec = suite.authedRequest(server, "POST", itemPath, contributorToken, map[string]any{
		"controlId": "ac-1", "componentUuid": componentUUID, "providedUuid": uuid.New().String(),
	})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	rec = suite.authedRequest(server, "POST", itemPath, contributorToken, map[string]any{
		"controlId": "ac-2", "statementId": stmtID, "componentUuid": componentUUID, "providedUuid": uuid.New().String(),
	})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	publishPath := fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/publish", ssp.UUID, offeringID)

	// Viewer cannot publish.
	rec = suite.authedRequest(server, "POST", publishPath, viewerToken, nil)
	suite.Require().Equal(http.StatusForbidden, rec.Code, rec.Body.String())

	// Contributor can publish.
	rec = suite.authedRequest(server, "POST", publishPath, contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var published handler.GenericDataResponse[relational.SSPExportOffering]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &published))
	suite.Equal(relational.SSPExportOfferingStatusPublished, published.Data.Status)
	suite.Equal(1, published.Data.Version)
	suite.NotEmpty(published.Data.ContentHash)
	suite.Len(published.Data.Items, 2)

	// Viewer CAN read the published offering via the top-level catalog (ssp-export-offering:read).
	rec = suite.authedRequest(server, "GET", "/api/oscal/ssp-export-offerings/"+offeringID, viewerToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
}
