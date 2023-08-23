package v1_1

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

// ResponsibleRole A reference to a role with responsibility for performing a function relative to the containing object, optionally associated with a set of persons and/or organizations that perform that role.
type ResponsibleRole struct {
	Links      []*Link     `json:"links,omitempty"`
	PartyUuids []string    `json:"party-uuids,omitempty"`
	Props      []*Property `json:"props,omitempty"`
	Remarks    string      `json:"remarks,omitempty"`

	// A human-oriented identifier reference to a role performed.
	RoleId string `json:"role-id"`
}

// ResponsibleParty A reference to a set of persons and/or organizations that have responsibility for performing the referenced role in the context of the containing object.
type ResponsibleParty struct {
	Links      []*Link     `json:"links,omitempty"`
	PartyUuids []string    `json:"party-uuids"`
	Props      []*Property `json:"props,omitempty"`
	Remarks    string      `json:"remarks,omitempty"`

	// A reference to a role performed by a party.
	RoleId string `json:"role-id"`
}

// Role Defines a function, which might be assigned to a party in a specific situation.
type Role struct {

	// A summary of the role's purpose and associated responsibilities.
	Description string `json:"description,omitempty"`

	// A unique identifier for the role.
	Id      string      `json:"id"`
	Links   []*Link     `json:"links,omitempty"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`

	// A short common name, abbreviation, or acronym for the role.
	ShortName string `json:"short-name,omitempty"`

	// A name given to the role, which may be used by a tool for display and navigation.
	Title string `json:"title"`
}

// Party An organization or person, which may be associated with roles or other concepts within the current or linked OSCAL document.
type Party struct {
	Addresses             []*Address                 `json:"addresses,omitempty"`
	EmailAddresses        []interface{}              `json:"email-addresses,omitempty"`
	ExternalIds           []*PartyExternalIdentifier `json:"external-ids,omitempty"`
	Links                 []*Link                    `json:"links,omitempty"`
	LocationUuids         []string                   `json:"location-uuids,omitempty"`
	MemberOfOrganizations []string                   `json:"member-of-organizations,omitempty"`

	// The full name of the party. This is typically the legal name associated with the party.
	Name    string      `json:"name,omitempty"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`

	// A short common name, abbreviation, or acronym for the party.
	ShortName        string             `json:"short-name,omitempty"`
	TelephoneNumbers []*TelephoneNumber `json:"telephone-numbers,omitempty"`

	// A category describing the kind of party the object describes.
	Type interface{} `json:"type"`

	// A unique identifier for the party.
	Uuid string `json:"uuid"`
}

// Address A postal address for the location.
type Address struct {
	AddrLines []string `json:"addr-lines,omitempty"`

	// City, town or geographical region for the mailing address.
	City string `json:"city,omitempty"`

	// The ISO 3166-1 alpha-2 country code for the mailing address.
	Country string `json:"country,omitempty"`

	// Postal or ZIP code for mailing address.
	PostalCode string `json:"postal-code,omitempty"`

	// State, province or analogous geographical region for a mailing address.
	State string `json:"state,omitempty"`

	// Indicates the type of address.
	Type interface{} `json:"type,omitempty"`
}

// PartyExternalIdentifier An identifier for a person or organization using a designated scheme. e.g. an Open Researcher and Contributor ID (ORCID).
type PartyExternalIdentifier struct {
	Id string `json:"id"`

	// Indicates the type of external identifier.
	Scheme interface{} `json:"scheme"`
}

// TelephoneNumber A telephone service number as defined by ITU-T E.164.
type TelephoneNumber struct {
	Number string `json:"number"`

	// Indicates the type of phone number.
	Type interface{} `json:"type,omitempty"`
}

// CommonPortRange Where applicable this is the IPv4 port range on which the service operates.
type CommonPortRange struct {

	// Indicates the ending port number in a port range
	End interface{} `json:"end,omitempty"`

	// Indicates the starting port number in a port range
	Start interface{} `json:"start,omitempty"`

	// Indicates the transport type.
	Transport interface{} `json:"transport,omitempty"`
}

// ServiceProtocolInformation Information about the protocol used to provide a service.
type ServiceProtocolInformation struct {

	// The common name of the protocol, which should be the appropriate "service name" from the IANA Service Name and Transport Protocol Port Number Registry.
	Name       string             `json:"name"`
	PortRanges []*CommonPortRange `json:"port-ranges,omitempty"`

	// A human readable name for the protocol (e.g., Transport Layer Security).
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this service protocol information elsewhere in this or other OSCAL instances. The locally defined UUID of the service protocol can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid,omitempty"`
}

// SetParameterValue Identifies the parameter that will be set by the enclosed value.
type SetParameterValue struct {

	// A human-oriented reference to a parameter within a control, who's catalog has been imported into the current implementation context.
	ParamId string   `json:"param-id"`
	Remarks string   `json:"remarks,omitempty"`
	Values  []string `json:"values"`
}
