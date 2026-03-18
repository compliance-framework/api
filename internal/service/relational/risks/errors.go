package risks

import "errors"

type ValidationError struct {
	message string
}

var ErrRemediationTemplateAlreadyExists = errors.New("remediation template already exists")

func (e *ValidationError) Error() string {
	return e.message
}

func newValidationError(message string) error {
	return &ValidationError{message: message}
}

func IsValidationError(err error) bool {
	var validationErr *ValidationError
	return errors.As(err, &validationErr)
}

func IsRemediationTemplateAlreadyExistsError(err error) bool {
	return errors.Is(err, ErrRemediationTemplateAlreadyExists)
}
