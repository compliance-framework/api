package agentconfig

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }

// fieldErrors asserts err is a ValidationErrors and returns it.
func fieldErrors(t *testing.T, err error) ValidationErrors {
	t.Helper()
	require.Error(t, err)
	var ve ValidationErrors
	require.True(t, errors.As(err, &ve), "error is %T, want ValidationErrors: %v", err, err)
	require.NotEmpty(t, ve)
	return ve
}

// findFieldError returns the first error at path with code, or nil.
func findFieldError(errs ValidationErrors, path, code string) *FieldError {
	for i := range errs {
		if errs[i].Path == path && errs[i].Code == code {
			return &errs[i]
		}
	}
	return nil
}

// requireFieldError asserts that err contains a FieldError with path and code.
func requireFieldError(t *testing.T, err error, path, code string) FieldError {
	t.Helper()
	errs := fieldErrors(t, err)
	fe := findFieldError(errs, path, code)
	require.NotNil(t, fe, "no FieldError {path %q, code %q} in %#v", path, code, errs)
	return *fe
}
