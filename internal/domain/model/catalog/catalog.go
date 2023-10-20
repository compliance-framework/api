package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/domain/model"
)

type Catalog struct {
	Uuid model.Uuid `json:"uuid"`

	model.Metadata

	Params     []Parameter      `json:"params"`
	Controls   []model.Uuid     `json:"controlUuids"` // Reference to controls
	Groups     []model.Uuid     `json:"groupUuids"`   // Reference to groups
	BackMatter model.BackMatter `json:"backMatter"`
}
