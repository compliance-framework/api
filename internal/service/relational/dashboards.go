package relational

import (
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"gorm.io/datatypes"
)

type Dashboard struct {
	UUIDModel

	Name     string                                 `json:"name" yaml:"name"`
	Filter   datatypes.JSONType[labelfilter.Filter] `json:"filter" yaml:"filter"`
	Controls []Control                              `json:"controls" gorm:"many2many:dashboard_controls;"`
}
