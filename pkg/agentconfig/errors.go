package agentconfig

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// FieldError is one validation problem in a config document.
type FieldError struct {
	Path    string `json:"path"`    // RFC 6901 pointer into the snake_case config ("" = root)
	Code    string `json:"code"`    // stable machine code (R43), one of FieldCode*
	Message string `json:"message"` // human text
}

// FieldError codes (R43). The agent maps them to report reasons without its own pre-decode:
// unknown-field -> reason unknown-field; invalid-type -> invalid-type; env-missing ->
// env-missing; locked-key / forbidden-env -> forbidden-changes; everything else ->
// invalid-config.
const (
	FieldCodeUnknownField = "unknown-field" // key not in the schema (O4)
	FieldCodeInvalidType  = "invalid-type"  // wrong JSON type, e.g. a non-string config/labels value (O5)
	FieldCodeInvalidValue = "invalid-value" // right type, out of range / not in enum
	FieldCodeLockedKey    = "locked-key"    // api / daemon / remote_config in an overlay (O3)
	FieldCodeSize         = "size"          // overlay size limit (O2)
	FieldCodePattern      = "pattern"       // plugin name or glob pattern (O6)
	FieldCodeCron         = "cron"          // schedule does not parse (O7)
	FieldCodeDuration     = "duration"      // interval / poll_interval
	FieldCodeSource       = "source"        // empty plugin source or policy entry (O8)
	FieldCodeEnvLocation  = "env-location"  // ${env:} outside plugins.*.config (O9)
	FieldCodeForbiddenEnv = "forbidden-env" // ${env:CCF_API_AUTH_*} (O9)
	FieldCodeEnvMissing   = "env-missing"   // ResolveEnv: variable unset (agent only)
	FieldCodeMaskedValue  = "masked-value"  // "••••" submitted (O10)
	FieldCodeRequired     = "required"      // missing required field (api.url, plugin source, ...)
	FieldCodeParse        = "parse"         // not a JSON object
)

// ValidationErrors is a list of FieldErrors; it is the error type returned by the
// validators.
type ValidationErrors []FieldError

// Error implements error.
func (v ValidationErrors) Error() string {
	if len(v) == 0 {
		return "no validation errors"
	}
	parts := make([]string, 0, len(v))
	for _, e := range v {
		path := e.Path
		if path == "" {
			path = "/"
		}
		parts = append(parts, fmt.Sprintf("%s: %s", path, e.Message))
	}
	return strings.Join(parts, "; ")
}

// sortFieldErrors orders errors by path, then code, then message, and drops exact
// duplicates.
func sortFieldErrors(errs []FieldError) []FieldError {
	slices.SortFunc(errs, func(a, b FieldError) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.Code, b.Code), strings.Compare(a.Message, b.Message))
	})
	return slices.Compact(errs)
}

// asError returns nil for an empty list and the sorted ValidationErrors otherwise.
func asError(errs []FieldError) error {
	if len(errs) == 0 {
		return nil
	}
	return ValidationErrors(sortFieldErrors(errs))
}
