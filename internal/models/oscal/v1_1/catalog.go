package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/jsonschema"
	_ "github.com/compliance-framework/configuration-service/internal/jsonschema/httploader"
	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// Control A structured object representing a requirement or guideline, which when implemented will reduce an aspect of risk related to an information system and its information.
type Control struct {

	// A textual label that provides a sub-type or characterization of the catalog.
	Class    string     `json:"class,omitempty"`
	Controls []*Control `json:"controls,omitempty"`
	// Identifies a catalog such that it can be referenced in the defining catalog and other OSCAL instances (e.g., profiles).
	Id     string       `query:"id" json:"id"`
	Links  []*Link      `json:"links,omitempty"`
	Params []*Parameter `json:"params,omitempty"`
	Parts  []*Part      `json:"parts,omitempty"`
	Props  []*Property  `json:"props,omitempty"`

	// A name given to the catalog, which may be used by a tool for display and navigation.
	Title string `json:"title"`
}

// ControlGroup A group of controls, or of groups of controls.
type ControlGroup struct {

	// A textual label that provides a sub-type or characterization of the group.
	Class    string          `json:"class,omitempty"`
	Controls []*Control      `json:"controls,omitempty"`
	Groups   []*ControlGroup `json:"groups,omitempty"`

	// Identifies the group for the purpose of cross-linking within the defining instance or from other instances that reference the catalog.
	Id     string       `json:"id,omitempty"`
	Links  []*Link      `json:"links,omitempty"`
	Params []*Parameter `json:"params,omitempty"`
	Parts  []*Part      `json:"parts,omitempty"`
	Props  []*Property  `json:"props,omitempty"`

	// A name given to the group, which may be used by a tool for display and navigation.
	Title string `json:"title"`
}

// Catalog A structured, organized collection of catalog information.
type Catalog struct {
	BackMatter *BackMatter     `json:"back-matter,omitempty"`
	Controls   []*Control      `json:"controls,omitempty"`
	Groups     []*ControlGroup `json:"groups,omitempty"`
	// Metadata is not implemented right now, so we are defining a map[string]interface{} to allow any information here
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Params   []*Parameter           `json:"params,omitempty"`

	// Provides a globally unique means to identify a given catalog instance.
	Uuid string `json:"uuid" query:"uuid"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *Catalog) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *Catalog) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Catalog) DeepCopy() schema.BaseModel {
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

func (c *Catalog) UUID() string {
	return c.Uuid
}

// TODO Add tests
func (c *Catalog) Validate() error {

	sch, err := jsonschema.Compile("https://github.com/usnistgov/OSCAL/releases/download/v1.1.0/oscal_catalog_schema.json")
	if err != nil {
		return err
	}
	var p = map[string]interface{}{
		"catalog": c,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = json.Unmarshal(d, &p)
	if err != nil {
		return err
	}
	return sch.Validate(p)
}

func (c *Catalog) Type() string {
	return "catalogs"
}

func init() {
	schema.MustRegister("catalogs", &Catalog{})
}
