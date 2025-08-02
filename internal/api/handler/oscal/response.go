package oscal

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func NewValidationErrorResponse(errors []ValidationError) *echo.HTTPError {
	validationErrors := make(map[string][]string)
	for _, ve := range errors {
		if _, ok := validationErrors[ve.Field]; !ok {
			validationErrors[ve.Field] = []string{}
		}

		validationErrors[ve.Field] = append(validationErrors[ve.Field], ve.Message)
	}
	return echo.NewHTTPError(http.StatusBadRequest, map[string]any{"errors": validationErrors})
}
