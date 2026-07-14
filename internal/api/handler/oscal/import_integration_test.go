//go:build integration

package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/tests"
)

type ImportApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *ImportApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()
}

func TestImportApiIntegrationSuite(t *testing.T) {
	suite.Run(t, new(ImportApiIntegrationSuite))
}

// importSSPDocument posts one SSP JSON document to /api/oscal/import and returns the parsed
// per-file result.
func (suite *ImportApiIntegrationSuite) importSSPDocument(server *api.Server, document string) (ImportFileResult, int) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("files", "ssp.json")
	suite.Require().NoError(err)
	_, err = part.Write([]byte(document))
	suite.Require().NoError(err)
	suite.Require().NoError(writer.Close())

	req := httptest.NewRequest("POST", "/api/oscal/import", body)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))

	rec := httptest.NewRecorder()
	server.E().ServeHTTP(rec, req)

	var resp handler.GenericDataResponse[ImportResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Require().Len(resp.Data.Results, 1)
	return resp.Data.Results[0], rec.Code
}

// sspDocument renders a minimal but complete SSP with one statement-anchored by-component
// carrying the given implementation-status state.
func sspDocument(sspUUID, title, implementationState string) string {
	return fmt.Sprintf(`{
	  "system-security-plan": {
	    "uuid": %q,
	    "metadata": {
	      "title": %q,
	      "last-modified": "2024-01-01T00:00:00Z",
	      "version": "1.0.0",
	      "oscal-version": "1.1.3"
	    },
	    "import-profile": { "href": "#profile" },
	    "system-characteristics": {
	      "system-ids": [{ "id": "sys-1" }],
	      "system-name": "Test System",
	      "description": "d",
	      "security-sensitivity-level": "low",
	      "system-information": { "information-types": [] },
	      "security-impact-level": {
	        "security-objective-confidentiality": "low",
	        "security-objective-integrity": "low",
	        "security-objective-availability": "low"
	      },
	      "status": { "state": "operational" },
	      "authorization-boundary": { "description": "b" }
	    },
	    "system-implementation": {
	      "users": [],
	      "components": [{
	        "uuid": %q,
	        "type": "software",
	        "title": "Component",
	        "description": "d",
	        "status": { "state": "operational" }
	      }]
	    },
	    "control-implementation": {
	      "description": "ci",
	      "implemented-requirements": [{
	        "uuid": %q,
	        "control-id": "ac-2",
	        "statements": [{
	          "uuid": %q,
	          "statement-id": "ac-2_smt.a",
	          "by-components": [{
	            "uuid": %q,
	            "component-uuid": %q,
	            "description": "bc",
	            "implementation-status": { "state": %q }
	          }]
	        }]
	      }]
	    }
	  }
	}`,
		sspUUID, title,
		uuid.New().String(),
		uuid.New().String(),
		uuid.New().String(),
		uuid.New().String(),
		uuid.New().String(),
		implementationState,
	)
}

func (suite *ImportApiIntegrationSuite) newServer() *api.Server {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	suite.Require().NoError(suite.Migrator.Refresh())

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil, nil)
	return server
}

// TestImportRejectsInvalidImplementationStatus: import was the one write path into the SSP tree
// that never ran validateByComponentImplementationStatus, so a bad state sailed straight into
// the database via FirstOrCreate. It is now rejected.
func (suite *ImportApiIntegrationSuite) TestImportRejectsInvalidImplementationStatus() {
	server := suite.newServer()

	result, code := suite.importSSPDocument(server, sspDocument(uuid.New().String(), "Bad SSP", "totally-made-up"))

	suite.Equal(http.StatusBadRequest, code, "the only file failed, so the whole import is a 400")
	suite.False(result.Success)
	suite.Contains(result.Message, "totally-made-up")

	var count int64
	suite.Require().NoError(suite.DB.Table("system_security_plans").Count(&count).Error)
	suite.Zero(count, "nothing was written")
}

// TestImportAcceptsValidImplementationStatus is the control for the test above: a valid state
// still imports.
func (suite *ImportApiIntegrationSuite) TestImportAcceptsValidImplementationStatus() {
	server := suite.newServer()

	result, code := suite.importSSPDocument(server, sspDocument(uuid.New().String(), "Good SSP", "implemented"))

	suite.Equal(http.StatusOK, code)
	suite.True(result.Success)
	suite.Equal("Successfully imported system security plan", result.Message)
	suite.Equal("System Security Plan", result.Type)
}

// TestImportReportsNoOpOnExistingUUID: FirstOrCreate is keyed on the OSCAL UUID, so re-importing
// a *changed* SSP under an existing UUID matches the stored row and writes nothing at all.
// Reporting that as "Successfully imported" told the caller their edits had landed when they
// hadn't. The result now says plainly that nothing was written.
func (suite *ImportApiIntegrationSuite) TestImportReportsNoOpOnExistingUUID() {
	server := suite.newServer()
	sspUUID := uuid.New().String()

	first, code := suite.importSSPDocument(server, sspDocument(sspUUID, "Original title", "implemented"))
	suite.Require().Equal(http.StatusOK, code)
	suite.Require().True(first.Success)
	suite.Equal("Successfully imported system security plan", first.Message)

	// Same UUID, different content: FirstOrCreate matches and writes nothing.
	second, code := suite.importSSPDocument(server, sspDocument(sspUUID, "Revised title", "partial"))
	suite.Equal(http.StatusOK, code)
	suite.True(second.Success, "processing the file did not error — but nothing was written")
	suite.Contains(second.Message, "already exists")
	suite.Contains(second.Message, "nothing was written")
	suite.NotContains(second.Message, "Successfully imported")

	// Proof the no-op really was a no-op: still one SSP, still the original title.
	var count int64
	suite.Require().NoError(suite.DB.Table("system_security_plans").Count(&count).Error)
	suite.Equal(int64(1), count)
}
