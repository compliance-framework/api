package workflows

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestWorkflowImportRejectsTooManyFiles(t *testing.T) {
	e := echo.New()
	req := newMultipartRequest(t, maxImportFiles+1, []byte("[]"))
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	handler := NewWorkflowImportHandler(zap.NewNop().Sugar(), nil)

	err := handler.Import(ctx)

	require.NoError(t, err)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestWorkflowImportRejectsOversizedFileBeforeOpen(t *testing.T) {
	e := echo.New()
	req := newMultipartRequest(t, 1, bytes.Repeat([]byte("x"), maxImportFileBytes+1))
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	handler := NewWorkflowImportHandler(zap.NewNop().Sugar(), nil)

	err := handler.Import(ctx)

	require.NoError(t, err)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	var response WorkflowImportDataResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Equal(t, 1, response.Data.TotalFiles)
	require.Equal(t, 0, response.Data.SuccessfulFiles)
	require.Equal(t, 1, response.Data.FailedFiles)
	require.Contains(t, response.Data.Results[0].Message, "Payload too large")
}

func TestWorkflowImportBodyLimitAllowsMaxFilesAtMaxSize(t *testing.T) {
	e := echo.New()
	handler := NewWorkflowImportHandler(zap.NewNop().Sugar(), nil)
	e.POST("/workflows/import", handler.Import, echomiddleware.BodyLimit(WorkflowImportBodyLimit))

	content := bytes.Repeat([]byte(" "), maxImportFileBytes)
	content[0] = '['
	content[1] = ']'

	req := newMultipartRequest(t, maxImportFiles, content)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var response WorkflowImportDataResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Equal(t, maxImportFiles, response.Data.TotalFiles)
	require.Equal(t, maxImportFiles, response.Data.SuccessfulFiles)
	require.Equal(t, 0, response.Data.FailedFiles)
}

func newMultipartRequest(t *testing.T, fileCount int, content []byte) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i < fileCount; i++ {
		part, err := writer.CreateFormFile("files", "workflow.json")
		require.NoError(t, err)
		_, err = part.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/workflows/import", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}
