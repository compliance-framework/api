package domain

type ProviderConfiguration struct {
	Name    string            `json:"name"`
	Package string            `json:"package"`
	Version string            `json:"version"`
	Params  map[string]string `json:"params"`
}
