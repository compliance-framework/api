package relational

import (
	"time"

	"github.com/google/uuid"
)

// SSPLeverageSatisfaction records whether a downstream's SatisfiedControlImplementationResponsibility
// rows for a leveraged provided-control cover every upstream responsibility (full) or only some (partial).
type SSPLeverageSatisfaction string

const (
	SSPLeverageSatisfactionFull    SSPLeverageSatisfaction = "full"
	SSPLeverageSatisfactionPartial SSPLeverageSatisfaction = "partial"
)

// SSPLeverageStatus is the lifecycle state of an SSPLeverageLink.
type SSPLeverageStatus string

const (
	SSPLeverageStatusActive     SSPLeverageStatus = "active"
	SSPLeverageStatusDrifted    SSPLeverageStatus = "drifted"
	SSPLeverageStatusRevoked    SSPLeverageStatus = "revoked"
	SSPLeverageStatusSuperseded SSPLeverageStatus = "superseded"
)

// SSPLeverageLink records one downstream SSP's subscription to a single upstream
// SSPExportOfferingItem (BCH-1338 Phase 2). ProvidedUUID is copied by value from the
// offering item rather than a real FK into the upstream's Export subtree, keeping the
// link portable and tolerant of the upstream being on a different system entirely.
// InheritedUUID is a bare-value reference (not a GORM association) to the downstream's own
// InheritedControlImplementation row created by the same subscribe call; nothing needs to
// preload through it.
//
// LeveragedAuthUUID is an OPTIONAL reference to a downstream LeveragedAuthorization. Sharing
// is deliberately decoupled from authorizations: subscribe never creates one, so new links
// carry nil here. A Leveraged Authorization models the downstream's real Authority to
// Operate (granted by an external auditor) — an independent, human-authored registry, not a
// gate on importing. The pointer is retained (and non-nil) only for legacy links created
// before this decoupling, which the LA-lapse drift path still keys on.
type SSPLeverageLink struct {
	UUIDModel

	DownstreamSSPID uuid.UUID `json:"downstreamSspId" gorm:"type:uuid;not null;index;uniqueIndex:idx_ssp_leverage_links_unique,priority:1"`
	UpstreamSSPID   uuid.UUID `json:"upstreamSspId" gorm:"type:uuid;not null;index"`

	OfferingID      uuid.UUID `json:"offeringId" gorm:"type:uuid;not null;index"`
	OfferingVersion int       `json:"offeringVersion"`

	ControlID    string    `json:"controlId"`
	StatementID  *string   `json:"statementId,omitempty"`
	ProvidedUUID uuid.UUID `json:"providedUuid" gorm:"type:uuid;not null;uniqueIndex:idx_ssp_leverage_links_unique,priority:2"`

	InheritedUUID     uuid.UUID  `json:"inheritedUuid" gorm:"type:uuid;not null"`
	LeveragedAuthUUID *uuid.UUID `json:"leveragedAuthUuid,omitempty" gorm:"type:uuid"`

	Satisfaction SSPLeverageSatisfaction `json:"satisfaction" gorm:"not null"`
	Status       SSPLeverageStatus       `json:"status" gorm:"not null;default:active"`

	AttestedAt   *time.Time `json:"attestedAt,omitempty"`
	AttestedByID *uuid.UUID `json:"attestedById,omitempty" gorm:"type:uuid"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (SSPLeverageLink) TableName() string {
	return "ssp_leverage_links"
}
