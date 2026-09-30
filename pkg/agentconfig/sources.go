package agentconfig

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// SourceKind classifies a plugin source, policy entry or bundle extends value.
type SourceKind string

const (
	SourceKindInline SourceKind = "inline"
	SourceKindOCI    SourceKind = "oci"
	SourceKindLocal  SourceKind = "local"
)

// IsOCISource reports whether s parses as an OCI tag with strict validation, which is what
// the agent's downloader supports. The agent's internal.IsOCI delegates here (R3).
func IsOCISource(s string) bool {
	_, err := name.NewTag(s, name.StrictValidation)
	return err == nil
}

// IsInlineSource reports whether s refers to a policy bundle ("inline:<name>").
func IsInlineSource(s string) bool {
	return strings.HasPrefix(s, InlineSourcePrefix)
}

// InlineBundleName returns the bundle name of an "inline:<name>" source. ok is false when s
// is not inline or the name is empty. The name is not checked against BundleNamePattern.
func InlineBundleName(s string) (string, bool) {
	if !IsInlineSource(s) {
		return "", false
	}
	n := strings.TrimPrefix(s, InlineSourcePrefix)
	if n == "" {
		return "", false
	}
	return n, true
}

// KindOf classifies s: inline, OCI (strict tag) or, otherwise, a local path.
func KindOf(s string) SourceKind {
	switch {
	case IsInlineSource(s):
		return SourceKindInline
	case IsOCISource(s):
		return SourceKindOCI
	default:
		return SourceKindLocal
	}
}
