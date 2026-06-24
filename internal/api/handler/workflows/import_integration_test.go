//go:build integration

package workflows

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	workflowseed "github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const workflowImportFixture = `[
  {
    "key": "http-import-test",
    "name": "HTTP Import Test",
    "description": "Imported through HTTP",
    "version": "1.0.0",
    "suggested-cadence": "monthly",
    "grace-period-days": 5,
    "evidence-required": "Documented evidence",
    "steps": [
      {
        "name": "Collect evidence",
        "description": "Collect the evidence",
        "order": 1,
        "responsible-role": "control-owner",
        "evidence-required": [],
        "estimated-duration": 2,
        "depends-on": []
      },
      {
        "name": "Review evidence",
        "description": "Review the evidence",
        "order": 2,
        "responsible-role": "control-owner",
        "evidence-required": [],
        "estimated-duration": 1,
        "depends-on": ["Collect evidence"]
      }
    ],
    "control-relationships": [
      {
        "control-id": "ccf-001",
        "catalog-id": "0f9d8e10-363b-4a8f-ade5-f11c0b2b1202",
        "relationship-type": "satisfies",
        "strength": "primary",
        "is-active": true,
        "_title": "Ignored title"
      }
    ],
    "instances": []
  }
]`

func TestWorkflowImportHandlerImport(t *testing.T) {
	t.Run("single valid file", func(t *testing.T) {
		handler, db := setupWorkflowImportHandler(t)
		rec := performWorkflowImport(t, handler, map[string]string{"workflow.json": workflowImportFixture})

		require.Equal(t, http.StatusOK, rec.Code)
		response := decodeWorkflowImportResponse(t, rec)
		require.Equal(t, 1, response.Data.TotalFiles)
		require.Equal(t, 1, response.Data.SuccessfulFiles)
		require.Equal(t, 0, response.Data.FailedFiles)
		require.Len(t, response.Data.Results, 1)
		require.True(t, response.Data.Results[0].Success)
		require.Equal(t, 1, response.Data.Summary.DefinitionsCreated)
		require.Equal(t, 2, response.Data.Summary.Steps)
		require.Equal(t, 1, response.Data.Summary.Dependencies)
		require.Equal(t, 1, response.Data.Summary.ControlRelationships)

		var definitions int64
		require.NoError(t, db.Model(&workflowseed.WorkflowDefinition{}).Count(&definitions).Error)
		require.Equal(t, int64(1), definitions)
	})

	t.Run("two files aggregate counts", func(t *testing.T) {
		handler, _ := setupWorkflowImportHandler(t)
		second := bytes.ReplaceAll([]byte(workflowImportFixture), []byte("http-import-test"), []byte("http-import-test-two"))
		second = bytes.ReplaceAll(second, []byte("HTTP Import Test"), []byte("HTTP Import Test Two"))

		rec := performWorkflowImport(t, handler, map[string]string{
			"one.json": workflowImportFixture,
			"two.json": string(second),
		})

		require.Equal(t, http.StatusOK, rec.Code)
		response := decodeWorkflowImportResponse(t, rec)
		require.Equal(t, 2, response.Data.TotalFiles)
		require.Equal(t, 2, response.Data.SuccessfulFiles)
		require.Equal(t, 0, response.Data.FailedFiles)
		require.Equal(t, 2, response.Data.Summary.DefinitionsCreated)
		require.Equal(t, 4, response.Data.Summary.Steps)
		require.Equal(t, 2, response.Data.Summary.Dependencies)
		require.Equal(t, 2, response.Data.Summary.ControlRelationships)
	})

	t.Run("malformed file alongside valid file", func(t *testing.T) {
		handler, _ := setupWorkflowImportHandler(t)
		rec := performWorkflowImport(t, handler, map[string]string{
			"bad.json":   `[{`,
			"valid.json": workflowImportFixture,
		})

		require.Equal(t, http.StatusOK, rec.Code)
		response := decodeWorkflowImportResponse(t, rec)
		require.Equal(t, 2, response.Data.TotalFiles)
		require.Equal(t, 1, response.Data.SuccessfulFiles)
		require.Equal(t, 1, response.Data.FailedFiles)
		require.Equal(t, 1, response.Data.Summary.DefinitionsCreated)

		var sawFailed bool
		for _, result := range response.Data.Results {
			if !result.Success {
				sawFailed = true
				require.Contains(t, result.Message, "Failed to parse JSON")
			}
		}
		require.True(t, sawFailed)
	})

	t.Run("no files", func(t *testing.T) {
		handler, _ := setupWorkflowImportHandler(t)
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		require.NoError(t, writer.Close())

		req := httptest.NewRequest(http.MethodPost, "/workflows/import", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		ctx := echo.New().NewContext(req, rec)

		require.NoError(t, handler.Import(ctx))
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("repost updates existing rows", func(t *testing.T) {
		handler, db := setupWorkflowImportHandler(t)
		first := performWorkflowImport(t, handler, map[string]string{"workflow.json": workflowImportFixture})
		require.Equal(t, http.StatusOK, first.Code)

		second := performWorkflowImport(t, handler, map[string]string{"workflow.json": workflowImportFixture})
		require.Equal(t, http.StatusOK, second.Code)
		response := decodeWorkflowImportResponse(t, second)
		require.Equal(t, 0, response.Data.Summary.DefinitionsCreated)
		require.Equal(t, 1, response.Data.Summary.DefinitionsUpdated)

		var definitions int64
		require.NoError(t, db.Model(&workflowseed.WorkflowDefinition{}).Count(&definitions).Error)
		require.Equal(t, int64(1), definitions)
	})
}

func TestWorkflowImportRouteRequiresAdminGroup(t *testing.T) {
	db := setupTestDB(t)
	require.NoError(t, db.AutoMigrate(&relational.SSOUserLink{}))
	logger := zap.NewNop().Sugar()
	handler := NewWorkflowImportHandler(logger, db)

	user := relational.User{
		Email:      "non-admin@example.com",
		FirstName:  "Non",
		LastName:   "Admin",
		AuthMethod: "sso",
	}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&relational.SSOUserLink{
		UserID:     user.ID.String(),
		Provider:   "test",
		ExternalID: "non-admin",
		Email:      user.Email,
		Groups:     sso.SerializeStringArray([]string{"auditors"}),
		LastSync:   time.Now(),
	}).Error)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cfg := &config.Config{
		JWTPublicKey: &privateKey.PublicKey,
		SSO: &config.SSOConfig{
			Enabled: true,
			Providers: map[string]config.SSOProviderConfig{
				"test": {
					Name:                "test",
					RequiredAdminGroups: []string{"ccf-admins"},
				},
			},
		},
	}

	e := echo.New()
	group := e.Group("/workflows")
	group.Use(middleware.JWTMiddleware(cfg.JWTPublicKey))
	// Admin enforcement via the builtin-backed PEP, mirroring how the import route is gated in
	// production (pep.Authorize(admin, manage)); the builtin driver reproduces the prior
	// SSO-admin-group rule.
	adminPEP := middleware.NewPEP(authz.NewBuiltin(db, cfg, logger), authz.FailClosed, logger)
	group.POST(
		"/import",
		handler.Import,
		adminPEP.Authorize(authz.ResourceAdmin, authz.ActionManage),
		echomiddleware.BodyLimit(WorkflowImportBodyLimit),
	)

	token, err := authn.GenerateJWTToken(&user, privateKey)
	require.NoError(t, err)
	bodyLimit, err := strconv.ParseInt(WorkflowImportBodyLimit, 10, 64)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/workflows/import", http.NoBody)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
	req.Header.Set(echo.HeaderContentType, "multipart/form-data")
	req.ContentLength = bodyLimit + 1
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func setupWorkflowImportHandler(t *testing.T) (*WorkflowImportHandler, *gorm.DB) {
	t.Helper()

	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()
	return NewWorkflowImportHandler(logger, db), db
}

func performWorkflowImport(t *testing.T, handler *WorkflowImportHandler, files map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for filename, content := range files {
		part, err := writer.CreateFormFile("files", filename)
		require.NoError(t, err)
		_, err = part.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/workflows/import", body)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, rec)

	require.NoError(t, handler.Import(ctx))
	return rec
}

func decodeWorkflowImportResponse(t *testing.T, rec *httptest.ResponseRecorder) WorkflowImportDataResponse {
	t.Helper()

	var response WorkflowImportDataResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response), fmt.Sprintf("body: %s", rec.Body.String()))
	return response
}
