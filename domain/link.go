package domain

// Link
//
// Hyperlink
type Link struct {
	Href             string `json:"href"`
	MediaType        string `json:"mediaType"`
	Rel              string `json:"rel"`
	ResourceFragment string `json:"resourceFragment"`
	Text             string `json:"text"`
}
