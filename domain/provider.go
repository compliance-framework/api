package domain

type Provider struct {
	Uuid    Uuid   `json:"uuid"`
	Name    string `json:"name"`
	Package string `json:"package"`
	Version string `json:"version"`
}
