package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

type Catalog struct {
	Uuid oscal.Uuid `json:"uuid"`

	oscal.Metadata

	Params     []Parameter      `json:"params"`
	Controls   []oscal.Uuid     `json:"controlUuids"` // Reference to controls
	Groups     []oscal.Uuid     `json:"groupUuids"`   // Reference to groups
	BackMatter oscal.BackMatter `json:"backMatter"`
}
