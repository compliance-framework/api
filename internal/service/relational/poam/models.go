package poam

import (
	"fmt"
	"time"

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
	MilestoneStatusOpen       MilestoneStatus = "open"
	MilestoneStatusInProgress MilestoneStatus = "in-progress"
	MilestoneStatusCompleted  MilestoneStatus = "completed"
	MilestoneStatusCancelled  MilestoneStatus = "cancelled"
)

// IsValid reports whether the milestone status is one of the defined constants.
func (s MilestoneStatus) IsValid() bool {
	switch s {
	case MilestoneStatusOpen, MilestoneStatusInProgress, MilestoneStatusCompleted, MilestoneStatusCancelled:
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
	AcceptanceRationale   *string    `                                                 json:"acceptanceRationale,omitempty"`
	// ResourceRequired is a free-text planning field describing effort or budget needed.
	// Point-of-contact identity is expressed via PrimaryOwnerUserID (a FK to the users table)
	// rather than free-text poc_name/poc_email fields.
	ResourceRequired   *string   `gorm:"type:text" json:"resourceRequired,omitempty"`
	LastStatusChangeAt time.Time `gorm:"not null"                                  json:"lastStatusChangeAt"`
	CreatedAt          time.Time `                                                 json:"createdAt"`
	UpdatedAt          time.Time `                                                 json:"updatedAt"`

	// Associations — loaded on demand via Preload.
	Milestones    []PoamItemMilestone    `gorm:"foreignKey:PoamItemID;constraint:OnDelete:CASCADE" json:"milestones,omitempty"`
	RiskLinks     []PoamItemRiskLink     `gorm:"foreignKey:PoamItemID;constraint:OnDelete:CASCADE" json:"riskLinks,omitempty"`
	EvidenceLinks []PoamItemEvidenceLink `gorm:"foreignKey:PoamItemID;constraint:OnDelete:CASCADE" json:"evidenceLinks,omitempty"`
	ControlLinks  []PoamItemControlLink  `gorm:"foreignKey:PoamItemID;constraint:OnDelete:CASCADE" json:"controlLinks,omitempty"`
	FindingLinks  []PoamItemFindingLink  `gorm:"foreignKey:PoamItemID;constraint:OnDelete:CASCADE" json:"findingLinks,omitempty"`
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
	ID                    uuid.UUID  `gorm:"type:uuid;primaryKey"     json:"id"`
	PoamItemID            uuid.UUID  `gorm:"type:uuid;index;not null" json:"poamItemId"`
	Title                 string     `gorm:"not null"                 json:"title"`
	Description           string     `                                json:"description"`
	Status                string     `gorm:"type:text;not null"       json:"status"`
	PlannedCompletionDate *time.Time `                                json:"plannedCompletionDate,omitempty"`
	CompletionDate        *time.Time `                                json:"completionDate,omitempty"`
	ResponsibleParty      *string    `                                json:"responsibleParty,omitempty"`
	Remarks               *string    `                                json:"remarks,omitempty"`
	OrderIndex            int        `gorm:"not null;default:0"       json:"orderIndex"`
	CreatedAt             time.Time  `                                json:"createdAt"`
	UpdatedAt             time.Time  `                                json:"updatedAt"`
}

// TableName returns the physical table name.
func (PoamItemMilestone) TableName() string { return "ccf_poam_item_milestones" }

// BeforeCreate auto-assigns a UUID and validates enum fields.
func (m *PoamItemMilestone) BeforeCreate(_ *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.Status == "" {
		m.Status = string(MilestoneStatusOpen)
	}
	if !MilestoneStatus(m.Status).IsValid() {
		return fmt.Errorf("invalid milestone status: %s", m.Status)
	}
	return nil
}

// PoamItemRiskLink is the join table linking PoamItems to Risks.
// Uses a composite primary key and OnDelete:CASCADE to match the Risk service
// link table pattern (e.g., risk_evidence_links).
//
// Note: only the PoamItem side carries a DB-level FK constraint. The RiskID
// column intentionally has no FK back to the risks table because Risks live in
// a separate bounded context. Referential integrity on the Risk side is
// enforced at the application layer (EnsureExists checks before link creation).
type PoamItemRiskLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;primaryKey"       json:"poamItemId"`
	RiskID     uuid.UUID `gorm:"type:uuid;primaryKey;index" json:"riskId"`
	CreatedAt  time.Time `                                  json:"createdAt"`
	PoamItem   *PoamItem `json:"-" gorm:"foreignKey:PoamItemID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName returns the physical table name.
func (PoamItemRiskLink) TableName() string { return "ccf_poam_item_risk_links" }

// PoamItemEvidenceLink is the join table linking PoamItems to Evidence records.
// EvidenceID has no DB-level FK (same cross-context reasoning as PoamItemRiskLink).
type PoamItemEvidenceLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;primaryKey"       json:"poamItemId"`
	EvidenceID uuid.UUID `gorm:"type:uuid;primaryKey;index" json:"evidenceId"`
	CreatedAt  time.Time `                                  json:"createdAt"`
	PoamItem   *PoamItem `json:"-" gorm:"foreignKey:PoamItemID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName returns the physical table name.
func (PoamItemEvidenceLink) TableName() string { return "ccf_poam_item_evidence_links" }

// PoamItemControlLink is the join table linking PoamItems to Controls.
// CatalogID/ControlID have no DB-level FK (same cross-context reasoning as PoamItemRiskLink).
type PoamItemControlLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;primaryKey"             json:"poamItemId"`
	CatalogID  uuid.UUID `gorm:"type:uuid;primaryKey;index"       json:"catalogId"`
	ControlID  string    `gorm:"type:text;not null;primaryKey"    json:"controlId"`
	CreatedAt  time.Time `                                        json:"createdAt"`
	PoamItem   *PoamItem `json:"-" gorm:"foreignKey:PoamItemID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName returns the physical table name.
func (PoamItemControlLink) TableName() string { return "ccf_poam_item_control_links" }

// PoamItemFindingLink is the join table linking PoamItems to Findings.
// FindingID has no DB-level FK (same cross-context reasoning as PoamItemRiskLink).
type PoamItemFindingLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;primaryKey"       json:"poamItemId"`
	FindingID  uuid.UUID `gorm:"type:uuid;primaryKey;index" json:"findingId"`
	CreatedAt  time.Time `                                  json:"createdAt"`
	PoamItem   *PoamItem `json:"-" gorm:"foreignKey:PoamItemID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName returns the physical table name.
func (PoamItemFindingLink) TableName() string { return "ccf_poam_item_finding_links" }

// ControlRef is a typed reference to a control within a catalog.
type ControlRef struct {
	CatalogID uuid.UUID `json:"catalogId"`
	ControlID string    `json:"controlId"`
}
