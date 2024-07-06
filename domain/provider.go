package domain

type Provider struct {
	Name          string            `json:"name"`
	Package       string            `json:"package"`
	Image         string            `json:"image"`
	Tag           string            `json:"tag"`
	Configuration map[string]string `json:"configuration"`
	Params        map[string]string `json:"params"`
}
