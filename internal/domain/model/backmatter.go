package model

// Resource represents a resource associated with content in the containing document instance.
type Resource struct {
	Base64      *Base64              `json:"base64,omitempty"`       // A resource encoded using the Base64 alphabet.
	Citation    *Citation            `json:"citation,omitempty"`     // An optional citation associated with the resource.
	Description string               `json:"description,omitempty"`  // An optional short summary of the resource.
	DocumentIds []DocumentIdentifier `json:"document-ids,omitempty"` // Document identifiers associated with the resource.
	Props       []Property           `json:"props,omitempty"`        // Properties of the resource.
	Remarks     string               `json:"remarks,omitempty"`      // Remarks about the resource.
	Rlinks      []Link               `json:"rlinks,omitempty"`       // Related links of the resource.
	Title       string               `json:"title,omitempty"`        // An optional name given to the resource.
	Uuid        Uuid                 `json:"uuid"`                   // A unique identifier for a resource.
}

// BackMatter represents the back matter of a document with associated resources.
type BackMatter struct {
	Resources []*Resource `json:"resources,omitempty"`
}

// Base64 represents a resource encoded using the Base64 alphabet defined by RFC 2045.
type Base64 struct {
	Filename  string `json:"filename,omitempty"`   // Name of the file before it was encoded as Base64.
	MediaType string `json:"media-type,omitempty"` // A label that indicates the nature of a resource.
	Value     string `json:"value"`                // The Base64 encoded value.
}

// Citation represents an optional citation consisting of end note text using structured markup.
type Citation struct {
	Links []Link     `json:"links,omitempty"` // Links associated with the citation.
	Props []Property `json:"props,omitempty"` // Properties of the citation.
	Text  string     `json:"text"`            // A line of citation text.
}

// DocumentIdentifier represents a document identifier qualified by an identifier scheme.
type DocumentIdentifier struct {
	Identifier string      `json:"identifier"`       // The document identifier.
	Scheme     interface{} `json:"scheme,omitempty"` // Qualifies the kind of document identifier using a URI.
}
