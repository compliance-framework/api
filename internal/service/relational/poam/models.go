package poam

import (
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PoamItemStatus represents the lifecycle state of a POAM item.
type PoamItemStatus string

const (
	PoamItemStatusOpen       PoamItemStatus = "open"
	PoamItemStatusInProgress PoamItemStatus = "in-progress"
	PoamItemStatusCompleted  PoamItemStatus = "completed"
	PoamItemStatusOverdue    PoamItemStatus = "overdue"
)

// IsValid reports whether the status value is one of the defined constants.
func (s PoamItemStatus) IsValid() bool {
	switch s {
	case PoamItemStatusOpen, PoamItemStatusInProgress, PoamItemStatusCompleted, PoamItemStatusOverdue:
		return true
	}
	return false
}

// PoamItemSourceType describes how a POAM item was created.
type PoamItemSourceType string

const (
	PoamItemSourceTypeManual        PoamItemSourceType = "manual"
	PoamItemSourceTypeRiskPromotion PoamItemSourceType = "risk-promotion"
	PoamItemSourceTypeImport        PoamItemSourceType = "import"
)

// IsValid reports whether the source type value is one of the defined constants.
func (s PoamItemSourceType) IsValid() bool {
	switch s {
	case PoamItemSourceTypeManual, PoamItemSourceTypeRiskPromotion, PoamItemSourceTypeImport:
		return true
	}
	return false
}

// MilestoneStatus represents the lifecycle state of a POAM milestone.
type MilestoneStatus string

const (
	MilestoneStatusPlanned   MilestoneStatus = "planned"
	MilestoneStatusCompleted MilestoneStatus = "completed"
)

// IsValid reports whether the milestone status is one of the defined constants.
func (s MilestoneStatus) IsValid() bool {
	switch s {
	case MilestoneStatusPlanned, MilestoneStatusCompleted:
		return true
	}
	return false
}

// PoamItem is the primary GORM model for a POAM item.
// Field names follow the Confluence design doc (v15).
type PoamItem struct {
	ID                    uuid.UUID  `gorm:"type:uuid;primaryKey"                      json:"id"`
	SspID                 uuid.UUID  `gorm:"type:uuid;not null;index"                  json:"sspId"`
	Title                 string     `gorm:"not null"                                  json:"title"`
	Description           string     `                                                 json:"description"`
	Status                string     `gorm:"type:text;not null"                        json:"status"`
	SourceType            string     `gorm:"type:text;not null"                        json:"sourceType"`
	PrimaryOwnerUserID    *uuid.UUID `gorm:"type:uuid"                                 json:"primaryOwnerUserId,omitempty"`
	PlannedCompletionDate *time.Time `                                                 json:"plannedCompletionDate,omitempty"`
	CompletedAt           *time.Time `                                                 json:"completedAt,omitempty"`
	CreatedFromRiskID     *uuid.UUID `gorm:"type:uuid"                                 json:"createdFromRiskId,omitempty"`
	AcceptanceRationale   *string    `                                                 json:"acceptanceRationale,omitempty"`
	LastStatusChangeAt    time.Time  `gorm:"not null"                                  json:"lastStatusChangeAt"`
	CreatedAt             time.Time  `                                                 json:"createdAt"`
	UpdatedAt             time.Time  `                                                 json:"updatedAt"`

	// Associations — loaded on demand via Preload.
	Milestones []PoamItemMilestone `gorm:"foreignKey:PoamItemID;constraint:OnDelete:CASCADE" json:"milestones,omitempty"`
}

// TableName returns the physical table name.
func (PoamItem) TableName() string { return "ccf_poam_items" }

// BeforeCreate auto-assigns a UUID and validates enum fields.
func (p *PoamItem) BeforeCreate(_ *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.Status == "" {
		p.Status = string(PoamItemStatusOpen)
	}
	if p.SourceType == "" {
		p.SourceType = string(PoamItemSourceTypeManual)
	}
	if !PoamItemStatus(p.Status).IsValid() {
		return fmt.Errorf("invalid poam item status: %s", p.Status)
	}
	if !PoamItemSourceType(p.SourceType).IsValid() {
		return fmt.Errorf("invalid poam item source type: %s", p.SourceType)
	}
	if p.LastStatusChangeAt.IsZero() {
		p.LastStatusChangeAt = time.Now().UTC()
	}
	return nil
}

// PoamItemMilestone is a strong-typed milestone entry for a PoamItem.
// Field names follow the Confluence design doc (v15).
type PoamItemMilestone struct {
	ID                      uuid.UUID  `gorm:"type:uuid;primaryKey"     json:"id"`
	PoamItemID              uuid.UUID  `gorm:"type:uuid;index;not null" json:"poamItemId"`
	Title                   string     `gorm:"not null"                 json:"title"`
	Description             string     `                                json:"description"`
	Status                  string     `gorm:"type:text;not null"       json:"status"`
	ScheduledCompletionDate *time.Time `                                json:"scheduledCompletionDate,omitempty"`
	CompletionDate          *time.Time `                                json:"completionDate,omitempty"`
	OrderIndex              int        `gorm:"not null;default:0"       json:"orderIndex"`
	CreatedAt               time.Time  `                                json:"createdAt"`
	UpdatedAt               time.Time  `                                json:"updatedAt"`
}

// TableName returns the physical table name.
func (PoamItemMilestone) TableName() string { return "ccf_poam_item_milestones" }

// BeforeCreate auto-assigns a UUID and validates enum fields.
func (m *PoamItemMilestone) BeforeCreate(_ *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.Status == "" {
		m.Status = string(MilestoneStatusPlanned)
	}
	if !MilestoneStatus(m.Status).IsValid() {
		return fmt.Errorf("invalid milestone status: %s", m.Status)
	}
	return nil
}

// PoamItemRiskLink is the join table linking PoamItems to Risks.
type PoamItemRiskLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_risk_links_unique,unique" json:"poamItemId"`
	RiskID     uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_risk_links_unique,unique" json:"riskId"`
}

// TableName returns the physical table name.
func (PoamItemRiskLink) TableName() string { return "ccf_poam_item_risk_links" }

// PoamItemEvidenceLink is the join table linking PoamItems to Evidence records.
type PoamItemEvidenceLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_evidence_links_unique,unique" json:"poamItemId"`
	EvidenceID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_evidence_links_unique,unique" json:"evidenceId"`
}

// TableName returns the physical table name.
func (PoamItemEvidenceLink) TableName() string { return "ccf_poam_item_evidence_links" }

// PoamItemControlLink is the join table linking PoamItems to Controls.
type PoamItemControlLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_control_links_unique,unique" json:"poamItemId"`
	CatalogID  uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_control_links_unique,unique" json:"catalogId"`
	ControlID  string    `gorm:"type:text;not null;index:ccf_poam_item_control_links_unique,unique" json:"controlId"`
}

// TableName returns the physical table name.
func (PoamItemControlLink) TableName() string { return "ccf_poam_item_control_links" }

// PoamItemFindingLink is the join table linking PoamItems to Findings.
type PoamItemFindingLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_finding_links_unique,unique" json:"poamItemId"`
	FindingID  uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_finding_links_unique,unique" json:"findingId"`
}

// TableName returns the physical table name.
func (PoamItemFindingLink) TableName() string { return "ccf_poam_item_finding_links" }

// ControlRef is a typed reference to a control within a catalog.
type ControlRef struct {
	CatalogID uuid.UUID `json:"catalogId"`
	ControlID string    `json:"controlId"`
}

// Ensure the relational package is imported (used for SSP existence checks in the service).
var _ = relational.SystemSecurityPlan{}
