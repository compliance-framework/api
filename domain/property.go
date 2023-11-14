package domain

type Property struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Group   string `json:"group"`
	Ns      string `json:"ns"`
	Remarks string `json:"remarks"`
	Value   string `json:"value"`
}
