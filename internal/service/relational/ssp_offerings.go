package relational

import (
	"time"

	"github.com/google/uuid"
)

// SSPExportOfferingStatus is the lifecycle state of an SSPExportOffering.
type SSPExportOfferingStatus string

const (
	SSPExportOfferingStatusDraft      SSPExportOfferingStatus = "draft"
	SSPExportOfferingStatusPublished  SSPExportOfferingStatus = "published"
	SSPExportOfferingStatusDeprecated SSPExportOfferingStatus = "deprecated"
	SSPExportOfferingStatusRevoked    SSPExportOfferingStatus = "revoked"
)

// SSPExportOffering is a versioned, publishable subset of an upstream SSP's control
// implementations (BCH-1337 Phase 1). Curated in draft, then published via the
// SyncExportOffering chokepoint, which recomputes ContentHash and bumps Version only
// when the offering's content actually changed.
type SSPExportOffering struct {
	UUIDModel

	SSPID uuid.UUID `json:"sspId" gorm:"type:uuid;not null;index"`

	Title       string `json:"title"`
	Description string `json:"description"`

	Version     int                     `json:"version"`
	Status      SSPExportOfferingStatus `json:"status" gorm:"not null;default:draft"`
	ContentHash string                  `json:"contentHash"`
	PublishedAt *time.Time              `json:"publishedAt,omitempty"`

	CreatedByID *uuid.UUID `json:"createdById,omitempty" gorm:"type:uuid;index"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Items []SSPExportOfferingItem `json:"items,omitempty" gorm:"foreignKey:OfferingID;references:ID"`

	SystemSecurityPlan *SystemSecurityPlan `json:"-" gorm:"foreignKey:SSPID;references:ID"`
}

func (SSPExportOffering) TableName() string {
	return "ssp_export_offerings"
}

// SSPExportOfferingItem is one offered capability within an SSPExportOffering: a
// control (optionally scoped to a single statement) implemented by a component, whose
// leverageable capability is described by a ProvidedControlImplementation on that
// component's Export.
type SSPExportOfferingItem struct {
	UUIDModel

	OfferingID uuid.UUID `json:"offeringId" gorm:"type:uuid;not null;index"`

	ControlID     string    `json:"controlId"`
	StatementID   *string   `json:"statementId,omitempty"`
	ComponentUUID uuid.UUID `json:"componentUuid" gorm:"type:uuid"`
	ProvidedUUID  uuid.UUID `json:"providedUuid" gorm:"type:uuid"`

	Offering *SSPExportOffering `json:"-" gorm:"foreignKey:OfferingID;references:ID;constraint:OnDelete:CASCADE"`
}

func (SSPExportOfferingItem) TableName() string {
	return "ssp_export_offering_items"
}

// SSPExportOfferingAllowedDownstream is one entry in an offering's downstream-SSP
// allow-list (BCH-1342): if an offering has at least one row here, only the listed
// downstream SSPs may subscribe to it; an offering with zero rows keeps today's
// type-level default (any downstream permitted, subject to the existing ssp:update and
// contributor-role checks). Enforced by a handler-level check in Subscribe
// (ssp_leverage.go), not by the PDP — see internal/authz/manifest.yaml's
// allowed_downstreams attribute comment for why.
type SSPExportOfferingAllowedDownstream struct {
	OfferingID      uuid.UUID `json:"offeringId" gorm:"type:uuid;primaryKey"`
	DownstreamSSPID uuid.UUID `json:"downstreamSspId" gorm:"type:uuid;primaryKey"`

	Offering *SSPExportOffering `json:"-" gorm:"foreignKey:OfferingID;references:ID;constraint:OnDelete:CASCADE"`
}

func (SSPExportOfferingAllowedDownstream) TableName() string {
	return "ssp_export_offering_allowed_downstreams"
}
