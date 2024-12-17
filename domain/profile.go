package domain

// Profile is a collection of controls and metadata that can be used to create a new overlay or baseline.
// Note: The "Merge" and "Modify" are being skipped for now, as it doesn't make any sense to store the instructions for merging and modifying, rather than the result of applying them. They can be added as audit logs, holding all the details of the merge and modify operations.
type Profile struct {
	Uuid Uuid `json:"uuid" yaml:"uuid"`

	Metadata

	Imports    []Import   `json:"imports" yaml:"imports"`
	BackMatter BackMatter `json:"backmatter" yaml:"backmatter"`
}

// Import Designates a referenced source catalog or profile that provides a source of control information for use in creating a new overlay or baseline.
type Import struct {
	// Href is the URI of the source catalog or profile. Should be in the format `catalog/{catalog_uuid}` or `profile/{profile_uuid}`.
	Href            string      `json:"href" yaml:"href"`
	IncludeAll      bool        `json:"include_all" yaml:"include_all"`
	IncludeControls []Selection `json:"include_controls" yaml:"include_controls"`
	ExcludeControls []Selection `json:"exclude_controls" yaml:"exclude_controls"`
}

// ProfileSelection Selects a control or controls from an imported control set (Profile | Catalog).
type ProfileSelection struct {
	WithChildControls bool   `json:"with_child_controls" yaml:"with_child_controls"`
	WithIds           []Uuid `json:"with_ids" yaml:"with_ids"`
	Matching          []struct {
		Pattern string `json:"pattern" yaml:"pattern"`
	} `json:"matching" yaml:"matching"`
}
