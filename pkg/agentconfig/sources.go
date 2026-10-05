package agentconfig

import (
	"github.com/google/go-containerregistry/pkg/name"
)

// SourceKind classifies a plugin source or policy entry.
type SourceKind string

const (
	SourceKindOCI   SourceKind = "oci"
	SourceKindLocal SourceKind = "local"
)

// IsOCISource reports whether s parses as an OCI tag with strict validation, which is what
// the agent's downloader supports. The agent's internal.IsOCI delegates here (R3).
func IsOCISource(s string) bool {
	_, err := name.NewTag(s, name.StrictValidation)
	return err == nil
}

// KindOf classifies s: OCI (strict tag) or, otherwise, a local path.
func KindOf(s string) SourceKind {
	if IsOCISource(s) {
		return SourceKindOCI
	}
	return SourceKindLocal
}
