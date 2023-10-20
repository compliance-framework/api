package model

type Property struct {
	UUid    string `json:"uuid"`
	Class   string `json:"class"`
	Group   string `json:"group"`
	Ns      string `json:"ns"`
	Remarks string `json:"remarks"`
	Value   string `json:"value"`
}
