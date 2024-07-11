package domain

// Link
//
// Hyperlink
type Link struct {
	Href             string `json:"href" yaml:"href"`
	MediaType        string `json:"mediaType" yaml:"mediaType"`
	Rel              string `json:"rel" yaml:"rel"`
	ResourceFragment string `json:"resourceFragment" yaml:"resourceFragment"`
	Text             string `json:"text" yaml:"text"`
}
