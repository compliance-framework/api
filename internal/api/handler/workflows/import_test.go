package workflows

import (
	"bytes"
	"encoding/json"
	"io"
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
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
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

func TestWorkflowImportPropagatesBodyLimitDuringMultipartParsing(t *testing.T) {
	e := echo.New()
	handler := NewWorkflowImportHandler(zap.NewNop().Sugar(), nil)
	e.POST("/workflows/import", handler.Import, echomiddleware.BodyLimit("1000"))

	body, contentType := newMultipartBody(t, 1, bytes.Repeat([]byte("x"), 128*1024))
	req := httptest.NewRequest(http.MethodPost, "/workflows/import", io.NopCloser(&readerWithoutLen{
		reader: bytes.NewReader(body.Bytes()),
	}))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
}

func newMultipartRequest(t *testing.T, fileCount int, content []byte) *http.Request {
	t.Helper()

	body, contentType := newMultipartBody(t, fileCount, content)
	req := httptest.NewRequest(http.MethodPost, "/workflows/import", body)
	req.Header.Set("Content-Type", contentType)
	return req
}

func newMultipartBody(t *testing.T, fileCount int, content []byte) (*bytes.Buffer, string) {
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

	return &body, writer.FormDataContentType()
}

type readerWithoutLen struct {
	reader *bytes.Reader
}

func (r *readerWithoutLen) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}
