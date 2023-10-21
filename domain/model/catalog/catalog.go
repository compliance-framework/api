package catalog

import (
	model2 "github.com/compliance-framework/configuration-service/domain/model"
)

type Catalog struct {
	Uuid model2.Uuid `json:"uuid"`

	model2.Metadata

	Params     []Parameter       `json:"params"`
	Controls   []model2.Uuid     `json:"controlUuids"` // Reference to controls
	Groups     []model2.Uuid     `json:"groupUuids"`   // Reference to groups
	BackMatter model2.BackMatter `json:"backMatter"`
}
