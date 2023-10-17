package oscal

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Uuid string

type Metadata struct {
	Metadata metadata.Metadata `json:"metadata"`
}

type Props struct {
	Props []Property `json:"props,omitempty"`
}

type Links struct {
	Links []metadata.Link `json:"links,omitempty"`
}

type Remarks struct {
	Remarks string `json:"remarks,omitempty"`
}

type ComprehensiveDetails struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Props
	Links
	Remarks
}

type Selection struct {
	IncludeAll bool   `json:"includeAll"`
	Exclude    []Uuid `json:"exclude"`
	Include    []Uuid `json:"include"`
}
