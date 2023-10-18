package profile

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

// Profile is a collection of controls and metadata that can be used to create a new overlay or baseline.
// Note: The "Merge" and "Modify" are being skipped for now, as it doesn't make any sense to store the instructions for merging and modifying, rather than the result of applying them. They can be added as audit logs, holding all the details of the merge and modify operations.
type Profile struct {
	Uuid oscal.Uuid `json:"uuid"`

	oscal.Metadata

	Imports    []Import         `json:"imports"`
	BackMatter oscal.BackMatter `json:"backmatter"`
}

// Import Designates a referenced source catalog or profile that provides a source of control information for use in creating a new overlay or baseline.
type Import struct {
	// Href is the URI of the source catalog or profile. Should be in the format `catalog/{catalog_uuid}` or `profile/{profile_uuid}`.
	Href            string      `json:"href"`
	IncludeAll      bool        `json:"include_all"`
	IncludeControls []Selection `json:"include_controls"`
	ExcludeControls []Selection `json:"exclude_controls"`
}

// Selection Selects a control or controls from an imported control set (Profile | Catalog).
type Selection struct {
	WithChildControls bool         `json:"with_child_controls"`
	WithIds           []oscal.Uuid `json:"with_ids"`
	Matching          []struct {
		Pattern string `json:"pattern"`
	} `json:"matching"`
}
