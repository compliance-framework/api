package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

type Control struct {
	Uuid oscal.Uuid `json:"uuid"`

	oscal.Links
	oscal.Parts
	oscal.Props

	Class    string       `json:"class"`
	Title    string       `json:"title"`
	Params   []Parameter  `json:"params"`
	Controls []oscal.Uuid `json:"controlUuids"` // Reference to controls
}
