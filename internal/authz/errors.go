package authz

import (
	"errors"
	"strings"
)

// ErrUnavailable marks a PDP that could not produce a decision because the decision
// engine was unreachable or timed out. The PEP applies the configured fail mode when an
// Evaluate error wraps ErrUnavailable; any other error is treated as an internal server
// error (HTTP 500). The builtin driver runs in-process and never returns ErrUnavailable.
var ErrUnavailable = errors.New("authz: pdp unavailable")

// FailMode controls what the PEP does when the PDP is unavailable.
type FailMode string

const (
	// FailClosed denies the request on PDP error/timeout. This is the default.
	FailClosed FailMode = "closed"
	// FailOpen allows the request on PDP error/timeout.
	FailOpen FailMode = "open"
)

// ParseFailMode maps a config string to a FailMode, defaulting to FailClosed for any
// value other than "open".
func ParseFailMode(s string) FailMode {
	if strings.EqualFold(strings.TrimSpace(s), string(FailOpen)) {
		return FailOpen
	}
	return FailClosed
}
