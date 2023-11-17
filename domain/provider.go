package domain

type Provider struct {
	Name          string            `json:"name"`
	Package       string            `json:"package"`
	Version       string            `json:"version"`
	Configuration map[string]string `json:"configuration"`
	Params        map[string]string `json:"params"`
}
