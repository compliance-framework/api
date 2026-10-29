package oscal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
)

// A handler returning NewValidationErrorResponse gets a 400 whose body lists the messages per
// field, through echo's own error handler.
func TestValidationErrorResponseBody(t *testing.T) {
	e := echo.New()
	e.POST("/", func(c *echo.Context) error {
		return NewValidationErrorResponse([]ValidationError{
			{Field: "metadata.title", Message: "title is required"},
			{Field: "metadata.title", Message: "title is too short"},
			{Field: "import-ssp.href", Message: "href is required"},
		})
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", http.NoBody))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.JSONEq(t, `{"errors": {
		"metadata.title": ["title is required", "title is too short"],
		"import-ssp.href": ["href is required"]
	}}`, rec.Body.String())
}
