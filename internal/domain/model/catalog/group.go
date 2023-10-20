package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/domain/model"
)

type Group struct {
	Uuid model.Uuid `json:"uuid"`

	model.ComprehensiveDetails

	Class  string       `json:"class"`
	Params []Parameter  `json:"params"`
	Groups []model.Uuid `json:"groups"`
}
