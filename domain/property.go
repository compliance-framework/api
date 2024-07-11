package domain

type Property struct {
	Name    string `json:"name" yaml:"name"`
	Class   string `json:"class" yaml:"class"`
	Group   string `json:"group" yaml:"group"`
	Ns      string `json:"ns" yaml:"ns"`
	Remarks string `json:"remarks" yaml:"remarks"`
	Value   string `json:"value" yaml:"value"`
}
