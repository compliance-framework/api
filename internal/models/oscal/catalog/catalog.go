package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"github.com/compliance-framework/configuration-service/internal/models/oscal/metadata"
)

type Catalog struct {
	Uuid       oscal.Uuid        `json:"uuid"`
	Metadata   metadata.Metadata `json:"metadata"`
	Params     []Parameter       `json:"params"`
	Controls   []oscal.Uuid      `json:"controlUuids"` // Reference to controls
	Groups     []oscal.Uuid      `json:"groupUuids"`   // Reference to groups
	BackMatter oscal.BackMatter  `json:"backMatter"`
}
