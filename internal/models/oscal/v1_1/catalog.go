package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// BackMatter A collection of resources that may be referenced from within the OSCAL document instance.
type BackMatter struct {
	Resources []*Resource `json:"resources,omitempty"`
}

// Base64 A resource encoded using the Base64 alphabet defined by RFC 2045.
type Base64 struct {

	// Name of the file before it was encoded as Base64 to be embedded in a resource. This is the name that will be assigned to the file when the file is decoded.
	Filename string `json:"filename,omitempty"`

	// A label that indicates the nature of a resource, as a data serialization or format.
	MediaType string `json:"media-type,omitempty"`
	Value     string `json:"value"`
}

// Citation An optional citation consisting of end note text using structured markup.
type Citation struct {
	Links []*Link     `json:"links,omitempty"`
	Props []*Property `json:"props,omitempty"`

	// A line of citation text.
	Text string `json:"text"`
}

// Constraint A formal or informal expression of a constraint or test.
type Constraint struct {

	// A textual summary of the constraint to be applied.
	Description string            `json:"description,omitempty"`
	Tests       []*ConstraintTest `json:"tests,omitempty"`
}

// ConstraintTest A test expression which is expected to be evaluated by a tool.
type ConstraintTest struct {

	// A formal (executable) expression of a constraint.
	Expression string `json:"expression"`
	Remarks    string `json:"remarks,omitempty"`
}

// Control A structured object representing a requirement or guideline, which when implemented will reduce an aspect of risk related to an information system and its information.
type Control struct {

	// A textual label that provides a sub-type or characterization of the control.
	Class    string     `json:"class,omitempty"`
	Controls []*Control `json:"controls,omitempty"`
	// Identifies a control such that it can be referenced in the defining catalog and other OSCAL instances (e.g., profiles).
	Id     string       `query:"id" json:"id"`
	Links  []*Link      `json:"links,omitempty"`
	Params []*Parameter `json:"params,omitempty"`
	Parts  []*Part      `json:"parts,omitempty"`
	Props  []*Property  `json:"props,omitempty"`

	// A name given to the control, which may be used by a tool for display and navigation.
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

// DocumentIdentifier A document identifier qualified by an identifier scheme.
type DocumentIdentifier struct {
	Identifier string `json:"identifier"`

	// Qualifies the kind of document identifier using a URI. If the scheme is not provided the value of the element will be interpreted as a string of characters.
	Scheme interface{} `json:"scheme,omitempty"`
}

// Guideline A prose statement that provides a recommendation for the use of a parameter.
type Guideline struct {

	// Prose permits multiple paragraphs, lists, tables etc.
	Prose string `json:"prose"`
}

// Hash A representation of a cryptographic digest generated over a resource using a specified hash algorithm.
type Hash struct {

	// The digest method by which a hash is derived.
	Algorithm interface{} `json:"algorithm"`
	Value     string      `json:"value"`
}

// Link A reference to a local or remote resource, that has a specific relation to the containing object.
type Link struct {

	// A resolvable URL reference to a resource.
	Href string `json:"href"`

	// A label that indicates the nature of a resource, as a data serialization or format.
	MediaType string `json:"media-type,omitempty"`

	// Describes the type of relationship provided by the link's hypertext reference. This can be an indicator of the link's purpose.
	Rel interface{} `json:"rel,omitempty"`

	// In case where the href points to a back-matter/resource, this value will indicate the URI fragment to append to any rlink associated with the resource. This value MUST be URI encoded.
	ResourceFragment string `json:"resource-fragment,omitempty"`

	// A textual label to associate with the link, which may be used for presentation in a tool.
	Text string `json:"text,omitempty"`
}

// OscalCatalog A structured, organized collection of control information.
type OscalCatalog struct {
	BackMatter *BackMatter     `json:"back-matter,omitempty"`
	Controls   []*Control      `json:"controls,omitempty"`
	Groups     []*ControlGroup `json:"groups,omitempty"`
	// Metadata is not implemented right now, so we are defining a map[string]interface{} to allow any information here
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Params   []*Parameter           `json:"params,omitempty"`

	// Provides a globally unique means to identify a given catalog instance.
	Uuid string `json:"uuid"`
}

// Parameter Parameters provide a mechanism for the dynamic assignment of value(s) in a control.
type Parameter struct {

	// A textual label that provides a characterization of the type, purpose, use or scope of the parameter.
	Class       string        `json:"class,omitempty"`
	Constraints []*Constraint `json:"constraints,omitempty"`

	// (deprecated) Another parameter invoking this one. This construct has been deprecated and should not be used.
	DependsOn  string       `json:"depends-on,omitempty"`
	Guidelines []*Guideline `json:"guidelines,omitempty"`

	// A unique identifier for the parameter.
	Id string `json:"id"`

	// A short, placeholder name for the parameter, which can be used as a substitute for a value if no value is assigned.
	Label   string      `json:"label,omitempty"`
	Links   []*Link     `json:"links,omitempty"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`
	Select  *Selection  `json:"select,omitempty"`

	// Describes the purpose and use of a parameter.
	Usage  string   `json:"usage,omitempty"`
	Values []string `json:"values,omitempty"`
}

// Part An annotated, markup-based textual element of a control's or catalog group's definition, or a child of another part.
type Part struct {

	// An optional textual providing a sub-type or characterization of the part's name, or a category to which the part belongs.
	Class string `json:"class,omitempty"`

	// A unique identifier for the part.
	Id    string  `json:"id,omitempty"`
	Links []*Link `json:"links,omitempty"`

	// A textual label that uniquely identifies the part's semantic type, which exists in a value space qualified by the ns.
	Name string `json:"name"`

	// An optional namespace qualifying the part's name. This allows different organizations to associate distinct semantics with the same name.
	Ns    string      `json:"ns,omitempty"`
	Parts []*Part     `json:"parts,omitempty"`
	Props []*Property `json:"props,omitempty"`

	// Permits multiple paragraphs, lists, tables etc.
	Prose string `json:"prose,omitempty"`

	// An optional name given to the part, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty"`
}

// Property An attribute, characteristic, or quality of the containing object expressed as a namespace qualified name/value pair.
type Property struct {

	// A textual label that provides a sub-type or characterization of the property's name.
	Class string `json:"class,omitempty"`

	// An identifier for relating distinct sets of properties.
	Group string `json:"group,omitempty"`

	// A textual label, within a namespace, that uniquely identifies a specific attribute, characteristic, or quality of the property's containing object.
	Name string `json:"name"`

	// A namespace qualifying the property's name. This allows different organizations to associate distinct semantics with the same name.
	Ns      string `json:"ns,omitempty"`
	Remarks string `json:"remarks,omitempty"`

	// A unique identifier for a property.
	Uuid string `json:"uuid,omitempty"`

	// Indicates the value of the attribute, characteristic, or quality.
	Value string `json:"value"`
}

// Resource A resource associated with content in the containing document instance. A resource may be directly included in the document using base64 encoding or may point to one or more equivalent internet resources.
type Resource struct {

	// A resource encoded using the Base64 alphabet defined by RFC 2045.
	Base64 *Base64 `json:"base64,omitempty"`

	// An optional citation consisting of end note text using structured markup.
	Citation *Citation `json:"citation,omitempty"`

	// An optional short summary of the resource used to indicate the purpose of the resource.
	Description string                `json:"description,omitempty"`
	DocumentIds []*DocumentIdentifier `json:"document-ids,omitempty"`
	Props       []*Property           `json:"props,omitempty"`
	Remarks     string                `json:"remarks,omitempty"`
	Rlinks      []*ResourceLink       `json:"rlinks,omitempty"`

	// An optional name given to the resource, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty"`

	// A unique identifier for a resource.
	Uuid string `json:"uuid"`
}

// ResourceLink A URL-based pointer to an external resource with an optional hash for verification and change detection.
type ResourceLink struct {
	Hashes []*Hash `json:"hashes,omitempty"`

	// A resolvable URL pointing to the referenced resource.
	Href string `json:"href"`

	// A label that indicates the nature of a resource, as a data serialization or format.
	MediaType string `json:"media-type,omitempty"`
}

// Selection Presenting a choice among alternatives.
type Selection struct {
	Choice []string `json:"choice,omitempty"`

	// Describes the number of selections that must occur. Without this setting, only one value should be assumed to be permitted.
	HowMany interface{} `json:"how-many,omitempty"`
}

func (c *OscalCatalog) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *OscalCatalog) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *OscalCatalog) DeepCopy() schema.BaseModel {
	d := &OscalCatalog{}
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

func (c *OscalCatalog) Validate() error {
	//TODO Implement logic as defined in OSCAL
	return nil
}

func init() {
	schema.MustRegister("catalogs", &OscalCatalog{})
}
