package relational

import (
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"gorm.io/datatypes"
)

type Filter struct {
	UUIDModel

	Name     string                                 `json:"name" yaml:"name"`
	Filter   datatypes.JSONType[labelfilter.Filter] `json:"filter" yaml:"filter"`
	Controls []Control                              `json:"controls" gorm:"many2many:filter_controls;"`
}
