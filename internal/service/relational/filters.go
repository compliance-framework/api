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

// FilterResponsibility links a Filter to a specific upstream
// ControlImplementationResponsibility uuid, scoped to the downstream SSP whose
// ssp_leverage_links row it targets (BCH-1339). A sibling of the filter_controls
// many2many table, not an overload of it: filter_controls has no room for a third
// column, and the same upstream responsibility (via its provided-uuid) can be leveraged
// by multiple different downstream SSPs, so SSPID disambiguates which one this row
// targets — it is the downstream SSP id, matched against
// ssp_leverage_links.downstream_ssp_id.
type FilterResponsibility struct {
	FilterID uuid.UUID `json:"filterId" gorm:"type:uuid;primaryKey"`
	// ResponsibilityUUID and SSPID also carry idx_filter_responsibilities_ssp_lookup, a
	// composite index leading with ssp_id — the (filter_id, responsibility_uuid, ssp_id)
	// primary key leads with filter_id, which doesn't serve ResponsibilityPosture's
	// "WHERE ssp_id = ? AND responsibility_uuid IN ?" lookup (profile_compliance.go).
	ResponsibilityUUID uuid.UUID `json:"responsibilityUuid" gorm:"type:uuid;primaryKey;index:idx_filter_responsibilities_ssp_lookup,priority:2"`
	SSPID              uuid.UUID `json:"sspId" gorm:"type:uuid;primaryKey;index:idx_filter_responsibilities_ssp_lookup,priority:1"`

	Filter             *Filter             `json:"-" gorm:"foreignKey:FilterID;references:ID;constraint:OnDelete:CASCADE"`
	SystemSecurityPlan *SystemSecurityPlan `json:"-" gorm:"foreignKey:SSPID;references:ID;constraint:OnDelete:CASCADE"`
}

func (FilterResponsibility) TableName() string {
	return "filter_responsibilities"
}
