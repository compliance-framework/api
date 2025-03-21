package types

type Link struct {
	Href             string `json:"href" yaml:"href"`
	MediaType        string `json:"media-type,omitempty" yaml:"media-type,omitempty"`
	Rel              string `json:"rel,omitempty" yaml:"rel,omitempty"`
	ResourceFragment string `json:"resource-fragment,omitempty" yaml:"resource-fragment,omitempty"`
	Text             string `json:"text,omitempty" yaml:"text,omitempty"`
}

type Property struct {
	Class   string `json:"class,omitempty" yaml:"class,omitempty"`
	Group   string `json:"group,omitempty" yaml:"group,omitempty"`
	Name    string `json:"name" yaml:"name"`
	Ns      string `json:"ns,omitempty" yaml:"ns,omitempty"`
	Remarks string `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	UUID    string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Value   string `json:"value" yaml:"value"`
}
