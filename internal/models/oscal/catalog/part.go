package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Part struct {
	Uuid  string           `json:"uuid"`
	Name  string           `json:"name"`
	Ns    string           `json:"ns"`
	Class string           `json:"class"`
	Title string           `json:"title"`
	Props []oscal.Property `json:"props"`
	Parts []Part           `json:"parts"`
	Links []metadata.Link  `json:"links"`
}
