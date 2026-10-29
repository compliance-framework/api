package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewErrorReportsWhyABindFailed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": 1}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	ctx := echo.New().NewContext(req, httptest.NewRecorder())

	var body struct {
		Name string `json:"name"`
	}
	err := ctx.Bind(&body)
	require.Error(t, err)

	assert.Contains(t, NewError(err).Errors["body"], "cannot unmarshal number")
}

func TestNewErrorUsesTheMessageOfAnUnwrappedHTTPError(t *testing.T) {
	assert.Equal(t, "workflow_instance_id is required", NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_instance_id is required")).Errors["body"])
	assert.Equal(t, "plain", NewError(errors.New("plain")).Errors["body"])
}
