package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// ProfileImport Designates a referenced source catalog or profile that provides a source of control information for use in creating a new overlay or baseline.
type ProfileImport struct {
	ExcludeControls []*SelectControl `json:"exclude-controls,omitempty"`

	// A resolvable URL reference to the base catalog or profile that this profile is tailoring.
	Href            string           `json:"href"`
	IncludeAll      *IncludeAll      `json:"include-all,omitempty"`
	IncludeControls []*SelectControl `json:"include-controls,omitempty"`
}

// ProfileMerge Provides structuring directives that instruct how controls are organized after profile resolution.
type ProfileMerge struct {

	// Indicates that the controls selected should retain their original grouping as defined in the import source.
	AsIs bool `json:"as-is,omitempty"`

	// A Combine element defines how to resolve duplicate instances of the same control (e.g., controls with the same ID).
	Combine *CombinationRule `json:"combine,omitempty"`

	// Provides an alternate grouping structure that selected controls will be placed in.
	Custom *CustomGrouping `json:"custom,omitempty"`

	// Directs that controls appear without any grouping structure.
	Flat *FlatWithoutGrouping `json:"flat,omitempty"`
}

// ProfileModify Set parameters or amend controls in resolution.
type ProfileModify struct {
	Alters        []*Alteration       `json:"alters,omitempty"`
	SetParameters []*ParameterSetting `json:"set-parameters,omitempty"`
}

// Profile Each OSCAL profile is defined by a profile element.
type Profile struct {
	BackMatter *BackMatter            `json:"back-matter,omitempty"`
	Imports    []*ProfileImport       `json:"imports"`
	Merge      *ProfileMerge          `json:"merge,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
	Modify     *ProfileModify         `json:"modify,omitempty"`

	// Provides a globally unique means to identify a given profile instance.
	Uuid string `json:"uuid" query:"uuid"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *Profile) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *Profile) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Profile) DeepCopy() schema.BaseModel {
	d := &Catalog{}
	p, err := c.ToJSON()
	if err != nil {
		panic(err)
	}
	err = d.FromJSON(p)
	if err != nil {
		panic(err)
	}
	return d
}

func (c *Profile) UUID() string {
	return c.Uuid
}

func (c *Profile) Validate() error {
	//TODO Implement logic as defined in OSCAL
	return nil
}

func init() {
	schema.MustRegister("profiles", &Profile{})
}
