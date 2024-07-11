package domain

type Provider struct {
	Name          string            `json:"name" yaml:"name"`
	Image         string            `json:"image" yaml:"image"`
	Tag           string            `json:"tag" yaml:"tag"`
	Configuration map[string]string `json:"configuration" yaml:"configuration"`
}
