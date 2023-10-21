package catalog

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type Control struct {
	Uuid model.Uuid `json:"uuid"`

	model.Links
	model.Parts
	model.Props

	Class    string       `json:"class"`
	Title    string       `json:"title"`
	Params   []Parameter  `json:"params"`
	Controls []model.Uuid `json:"controlUuids"` // Reference to controls
}
