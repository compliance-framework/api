package oscal

import (
	"encoding/json"
	"net/http"
)

// ValidationErrorResponse is a 400 whose body is {"errors": {"<field>": ["<message>", ...]}}.
// Echo's error handler writes it as is: it reports its own status and marshals itself.
type ValidationErrorResponse struct {
	Errors map[string][]string `json:"errors"`
}

func (e *ValidationErrorResponse) Error() string {
	return "validation failed"
}

func (e *ValidationErrorResponse) StatusCode() int {
	return http.StatusBadRequest
}

func (e *ValidationErrorResponse) MarshalJSON() ([]byte, error) {
	type body ValidationErrorResponse // drops MarshalJSON, so this doesn't recurse
	return json.Marshal((*body)(e))
}

func NewValidationErrorResponse(errors []ValidationError) *ValidationErrorResponse {
	validationErrors := make(map[string][]string)
	for _, ve := range errors {
		if _, ok := validationErrors[ve.Field]; !ok {
			validationErrors[ve.Field] = []string{}
		}

		validationErrors[ve.Field] = append(validationErrors[ve.Field], ve.Message)
	}
	return &ValidationErrorResponse{Errors: validationErrors}
}
