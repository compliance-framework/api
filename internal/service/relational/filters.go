package relational

import (
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm/clause"
)

// Origins of a filter.
const (
	FilterOriginManual      = "manual"
	FilterOriginScopePolicy = "scope-policy"
)

const (
	// DefaultFilterBadgeLabel is the badge label of a filter that has not set one.
	DefaultFilterBadgeLabel = "compliance"
	// FilterBadgeSlugIndex is the partial unique index reserving badge slugs across all
	// filters, published or not.
	FilterBadgeSlugIndex = "idx_filters_badge_slug"
)

// FilterBadge holds a filter's public badge settings (docs/filter-badges.md). A slug is
// reserved while a filter holds it; the badge is public only while Enabled.
type FilterBadge struct {
	Enabled bool `json:"enabled" gorm:"column:badge_enabled;not null;default:false;check:chk_filters_badge_enabled_slug,badge_enabled = false OR badge_slug IS NOT NULL"`
	// Label is the plain-text left-hand side of the badge.
	Label string `json:"label" gorm:"column:badge_label;not null;default:compliance"`
	// Slug is the public identifier in /api/public/badges/{slug}.svg. Absent is NULL, never "".
	Slug *string `json:"slug" gorm:"column:badge_slug;uniqueIndex:idx_filters_badge_slug,where:badge_slug IS NOT NULL;check:chk_filters_badge_slug_not_empty,badge_slug IS NULL OR badge_slug <> ''"`
}

// DefaultFilterBadge returns the settings of an unpublished filter.
func DefaultFilterBadge() FilterBadge {
	return FilterBadge{Label: DefaultFilterBadgeLabel}
}

// FilterImportUpsert is the conflict clause for filter imports that may overwrite an
// existing filter by ID. It updates the imported fields only, so an import never
// copies, resets or clears another filter's badge settings.
func FilterImportUpsert() clause.OnConflict {
	return clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "ssp_id", "filter", "scope_base", "origin"}),
	}
}

type Filter struct {
	UUIDModel

	Name   string                                 `json:"name" yaml:"name"`
	SSPID  *uuid.UUID                             `json:"sspId,omitempty" yaml:"ssp_id,omitempty" gorm:"column:ssp_id;type:uuid;index"`
	Filter datatypes.JSONType[labelfilter.Filter] `json:"filter" yaml:"filter"`
	// ScopeBase, when set, makes the filter follow its SSP's scope: Filter is kept equal to
	// ScopeBase AND the SSP scope, and is rewritten whenever the scope changes.
	ScopeBase *datatypes.JSONType[labelfilter.Filter] `json:"scopeBase,omitempty" yaml:"-"`
	// Origin is "manual" for user-made filters and "scope-policy" for automatic per-policy
	// filters.
	Origin string `json:"origin" yaml:"-" gorm:"not null;default:manual"`
	// Badge is never imported or copied: imports, clones and generated filters start
	// unpublished.
	Badge      FilterBadge       `json:"badge" yaml:"-" gorm:"embedded"`
	Controls   []Control         `json:"controls" gorm:"many2many:filter_controls;"`
	Components []SystemComponent `json:"components" gorm:"many2many:filter_system_components;"`

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

	// Provenance of the filter→control association this attachment created. Attaching a
	// filter to a responsibility also links it to the responsibility's control (so the
	// existing control-level compliance surfaces include it); detaching must undo ONLY a
	// link the responsibility machinery itself created, never one a user made
	// independently via POST/PUT /api/filters. Semantics:
	//   - attach, link absent            → append filter_controls, ControlLinkCreated=true
	//   - attach, link present and some existing row on (filter_id, control_id) has
	//     ControlLinkCreated=true        → the link is responsibility-owned; the new row
	//     co-owns it (true), so the last detacher removes it
	//   - attach, link present otherwise → independently created, ControlLinkCreated=false
	//   - detach                         → remove the filter_controls row iff this row had
	//     ControlLinkCreated=true AND no other filter_responsibilities row on the same
	//     (filter_id, control_id) remains
	// Control's primary key is composite (catalog_id, id) — both parts are recorded so
	// detach can delete the exact association row.
	//
	// Rows are create/delete-only. Never Save()/Updates() this model: with a composite
	// primary key GORM's upsert semantics on partial keys are a footgun.
	ControlID        *string    `json:"controlId,omitempty" gorm:"column:control_id;index:idx_filter_responsibilities_control"`
	ControlCatalogID *uuid.UUID `json:"-" gorm:"column:control_catalog_id;type:uuid"`
	// ControlLinkCreated reports whether this attachment created (or co-owns) the
	// filter→control link — see the provenance comment above.
	ControlLinkCreated bool `json:"controlLinkCreated" gorm:"not null;default:false"`

	Filter             *Filter             `json:"-" gorm:"foreignKey:FilterID;references:ID;constraint:OnDelete:CASCADE"`
	SystemSecurityPlan *SystemSecurityPlan `json:"-" gorm:"foreignKey:SSPID;references:ID;constraint:OnDelete:CASCADE"`
}

func (FilterResponsibility) TableName() string {
	return "filter_responsibilities"
}
