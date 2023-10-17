package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Control struct {
	Uuid     string           `json:"uuid"`
	Class    string           `json:"class"`
	Title    string           `json:"title"`
	Params   []Parameter      `json:"params"`
	Props    []oscal.Property `json:"props"`
	Links    []metadata.Link  `json:"links"`
	Parts    []Part           `json:"parts"`
	Controls []oscal.Uuid     `json:"controlUuids"` // Reference to controls
}
