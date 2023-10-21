package catalog

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type Control struct {
	Uuid model.Uuid `json:"uuid"`

	Props []model.Property `json:"props,omitempty"`
	Links []model.Link     `json:"links,omitempty"`
	Parts []model.Part     `json:"parts,omitempty"`

	Class    string       `json:"class"`
	Title    string       `json:"title"`
	Params   []Parameter  `json:"params"`
	Controls []model.Uuid `json:"controlUuids"` // Reference to controls
}
