package catalog

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type Catalog struct {
	Uuid model.Uuid `json:"uuid"`

	Metadata model.Metadata `json:"metadata"`

	Params     []Parameter      `json:"params"`
	Controls   []model.Uuid     `json:"controlUuids"` // Reference to controls
	Groups     []model.Uuid     `json:"groupUuids"`   // Reference to groups
	BackMatter model.BackMatter `json:"backMatter"`
}

func NewCatalog() Catalog {
	return Catalog{
		Uuid: model.NewUuid(),
	}
}
