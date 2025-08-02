package oscal

import (
	"fmt"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
)

type Validatable interface {
	Validate() []ValidationError
}

type ValidationError struct {
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

var _ Validatable = (*AssessmentPlanCreateRequest)(nil)
var _ Validatable = (*AssessmentPlanUpdateRequest)(nil)

type AssessmentPlanCreateRequest struct {
	Data *oscalTypes.AssessmentPlan
}

func (ap *AssessmentPlanCreateRequest) Validate() []ValidationError {
	errors := baseAssessmentPlanValidate(ap.Data)
	return errors
}

type AssessmentPlanUpdateRequest struct {
	Data *oscalTypes.AssessmentPlan
}

func (ap *AssessmentPlanUpdateRequest) Validate() []ValidationError {
	errors := baseAssessmentPlanValidate(ap.Data)
	return errors
}

func baseAssessmentPlanValidate(plan *oscalTypes.AssessmentPlan) []ValidationError {
	errors := []ValidationError{}

	if plan == nil {
		errors = append(errors, ValidationError{
			Message: "assessment plan data is required",
			Field:   "data",
		})
		return errors
	}

	if plan.UUID == "" {
		errors = append(errors, ValidationError{
			Message: "UUID is required",
			Field:   "uuid",
		})
	} else if _, err := uuid.Parse(plan.UUID); err != nil {
		errors = append(errors, ValidationError{
			Message: fmt.Sprintf("invalid UUID format: %s", plan.UUID),
			Field:   "uuid",
		})
	}

	if plan.Metadata.Title == "" {
		errors = append(errors, ValidationError{
			Message: "metadata.title is required",
			Field:   "metadata.title",
		})
	}

	if plan.Metadata.Version == "" {
		errors = append(errors, ValidationError{
			Message: "metadata.version is required",
			Field:   "metadata.version",
		})
	}

	if plan.ImportSsp.Href == "" {
		errors = append(errors, ValidationError{
			Message: "import-ssp.href is required",
			Field:   "import-ssp.href",
		})
	}

	return errors
}
