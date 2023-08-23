package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// Addition Specifies contents to be added into controls, in resolution.
type Addition struct {

	// Target location of the addition.
	ById   string       `json:"by-id,omitempty"`
	Links  []*Link      `json:"links,omitempty"`
	Params []*Parameter `json:"params,omitempty"`
	Parts  []*Part      `json:"parts,omitempty"`

	// Where to add the new content with respect to the targeted element (beside it or inside it).
	Position interface{} `json:"position,omitempty"`
	Props    []*Property `json:"props,omitempty"`

	// A name given to the control, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty"`
}

// Alteration Specifies changes to be made to an included control when a profile is resolved.
type Alteration struct {
	Adds []*Addition `json:"adds,omitempty"`

	// A reference to a control with a corresponding id value. When referencing an externally defined control, the Control Identifier Reference must be used in the context of the external / imported OSCAL instance (e.g., uri-reference).
	ControlId string     `json:"control-id"`
	Removes   []*Removal `json:"removes,omitempty"`
}

// CombinationRule A Combine element defines how to resolve duplicate instances of the same control (e.g., controls with the same ID).
type CombinationRule struct {

	// Declare how clashing controls should be handled.
	Method interface{} `json:"method,omitempty"`
}

// CustomGrouping Provides an alternate grouping structure that selected controls will be placed in.
type CustomGrouping struct {
	Groups         []*ControlGroup   `json:"groups,omitempty"`
	InsertControls []*InsertControls `json:"insert-controls,omitempty"`
}

// FlatWithoutGrouping Directs that controls appear without any grouping structure.
type FlatWithoutGrouping struct {
}

// IncludeAll Include all controls from the imported catalog or profile resources.
type IncludeAll struct {
}

// InsertControls Specifies which controls to use in the containing context.
type InsertControls struct {
	ExcludeControls []*SelectControl `json:"exclude-controls,omitempty"`
	IncludeAll      *IncludeAll      `json:"include-all,omitempty"`
	IncludeControls []*SelectControl `json:"include-controls,omitempty"`

	// A designation of how a selection of controls in a profile is to be ordered.
	Order interface{} `json:"order,omitempty"`
}

// MatchControlsByPattern Selecting a set of controls by matching their IDs with a wildcard pattern.
type MatchControlsByPattern struct {

	// A glob expression matching the IDs of one or more controls to be selected.
	Pattern string `json:"pattern,omitempty"`
}

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

// ParameterSetting A parameter setting, to be propagated to points of insertion.
type ParameterSetting struct {

	// A textual label that provides a characterization of the parameter.
	Class       string        `json:"class,omitempty"`
	Constraints []*Constraint `json:"constraints,omitempty"`

	// **(deprecated)** Another parameter invoking this one. This construct has been deprecated and should not be used.
	DependsOn  string       `json:"depends-on,omitempty"`
	Guidelines []*Guideline `json:"guidelines,omitempty"`

	// A short, placeholder name for the parameter, which can be used as a substitute for a value if no value is assigned.
	Label string  `json:"label,omitempty"`
	Links []*Link `json:"links,omitempty"`

	// An identifier for the parameter.
	ParamId string      `json:"param-id"`
	Props   []*Property `json:"props,omitempty"`
	Select  *Selection  `json:"select,omitempty"`

	// Describes the purpose and use of a parameter.
	Usage  string   `json:"usage,omitempty"`
	Values []string `json:"values,omitempty"`
}

// Removal Specifies objects to be removed from a control based on specific aspects of the object that must all match.
type Removal struct {

	// Identify items to remove by matching their class.
	ByClass string `json:"by-class,omitempty"`

	// Identify items to remove indicated by their id.
	ById string `json:"by-id,omitempty"`

	// Identify items to remove by the name of the item's information object name, e.g. title or prop.
	ByItemName interface{} `json:"by-item-name,omitempty"`

	// Identify items remove by matching their assigned name.
	ByName string `json:"by-name,omitempty"`

	// Identify items to remove by the item's ns, which is the namespace associated with a part, or prop.
	ByNs string `json:"by-ns,omitempty"`
}

// SelectControl Select a control or controls from an imported control set.
type SelectControl struct {
	Matching []*MatchControlsByPattern `json:"matching,omitempty"`

	// When a control is included, whether its child (dependent) controls are also included.
	WithChildControls interface{} `json:"with-child-controls,omitempty"`
	WithIds           []string    `json:"with-ids,omitempty"`
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
