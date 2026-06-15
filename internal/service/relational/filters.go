package relational

import (
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Filter struct {
	UUIDModel

	Name       string                                 `json:"name" yaml:"name"`
	SSPID      *uuid.UUID                             `json:"sspId,omitempty" yaml:"ssp_id,omitempty" gorm:"column:ssp_id;type:uuid;index"`
	Filter     datatypes.JSONType[labelfilter.Filter] `json:"filter" yaml:"filter"`
	Controls   []Control                              `json:"controls" gorm:"many2many:filter_controls;"`
	Components []SystemComponent                      `json:"components" gorm:"many2many:filter_system_components;"`

	SystemSecurityPlan *SystemSecurityPlan `json:"-" gorm:"foreignKey:SSPID;references:ID;constraint:OnDelete:CASCADE"`
}
