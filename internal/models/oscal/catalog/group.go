package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Group struct {
	Uuid   oscal.Uuid       `json:"uuid"`
	Class  string           `json:"class"`
	Title  string           `json:"title"`
	Params []Parameter      `json:"params"`
	Props  []oscal.Property `json:"props"`
	Links  []metadata.Link  `json:"links"`
	Parts  []Part           `json:"parts"`
	Groups []oscal.Uuid     `json:"groups"`
}
