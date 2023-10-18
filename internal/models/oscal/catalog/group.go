package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
)

type Group struct {
	Uuid oscal.Uuid `json:"uuid"`

	oscal.ComprehensiveDetails

	Class  string       `json:"class"`
	Params []Parameter  `json:"params"`
	Groups []oscal.Uuid `json:"groups"`
}
