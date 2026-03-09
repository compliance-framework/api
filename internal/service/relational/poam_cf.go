package relational

import (
	"time"

	"github.com/google/uuid"
)

// CcfPoamItem is the first-class CCF POAM work item, always scoped to an SSP.
// Field names follow the Confluence design doc (v15) exactly.
// CCF-only fields are also exported as OSCAL Props (namespace ccf:) on OSCAL export.
type CcfPoamItem struct {
	ID                    uuid.UUID  `gorm:"type:uuid;primaryKey"                                                                                         json:"id"`
	SspID                 uuid.UUID  `gorm:"type:uuid;index;not null"                                                                                     json:"sspId"`
	Title                 string     `gorm:"not null"                                                                                                     json:"title"`
	Description           string     `gorm:"not null"                                                                                                     json:"description"`
	Status                string     `gorm:"type:text;index;not null"                                                                      json:"status"`
	PrimaryOwnerUserID    *uuid.UUID `gorm:"type:uuid;index"                                                                                              json:"primaryOwnerUserId,omitempty"`
	SourceType            string     `gorm:"type:text;not null;default:'manual'"                                                           json:"sourceType"`
	PlannedCompletionDate *time.Time `gorm:"index"                                                                                                        json:"plannedCompletionDate,omitempty"`
	CompletedAt           *time.Time `                                                                                                                    json:"completedAt,omitempty"`
	CreatedFromRiskID     *uuid.UUID `gorm:"type:uuid"                                                                                                    json:"createdFromRiskId,omitempty"`
	AcceptanceRationale   *string    `                                                                                                                    json:"acceptanceRationale,omitempty"`
	LastStatusChangeAt    time.Time  `gorm:"not null;autoCreateTime"                                                                                      json:"lastStatusChangeAt"`
	CreatedAt             time.Time  `                                                                                                                    json:"createdAt"`
	UpdatedAt             time.Time  `                                                                                                                    json:"updatedAt"`

	// Associations — loaded on demand
	Milestones []CcfPoamItemMilestone `gorm:"foreignKey:PoamItemID;constraint:OnDelete:CASCADE" json:"milestones,omitempty"`
}

func (CcfPoamItem) TableName() string { return "ccf_poam_items" }

// CcfPoamItemMilestone is a strong-typed milestone entry for a CcfPoamItem.
// Field names follow the Confluence design doc (v15).
type CcfPoamItemMilestone struct {
	ID                      uuid.UUID  `gorm:"type:uuid;primaryKey"                                                                    json:"id"`
	PoamItemID              uuid.UUID  `gorm:"type:uuid;index;not null"                                                                json:"poamItemId"`
	Title                   string     `gorm:"not null"                                                                                json:"title"`
	Description             string     `                                                                                               json:"description"`
	Status                  string     `gorm:"type:text;not null"                                             json:"status"`
	ScheduledCompletionDate *time.Time `                                                                                               json:"scheduledCompletionDate,omitempty"`
	CompletionDate          *time.Time `                                                                                               json:"completionDate,omitempty"`
	OrderIndex              int        `gorm:"not null;default:0"                                                                      json:"orderIndex"`
	CreatedAt               time.Time  `                                                                                               json:"createdAt"`
	UpdatedAt               time.Time  `                                                                                               json:"updatedAt"`
}

func (CcfPoamItemMilestone) TableName() string { return "ccf_poam_item_milestones" }

// CcfPoamItemRiskLink is the join table linking PoamItems to Risks.
type CcfPoamItemRiskLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_risk_links_unique,unique" json:"poamItemId"`
	RiskID     uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_risk_links_unique,unique" json:"riskId"`
}

func (CcfPoamItemRiskLink) TableName() string { return "ccf_poam_item_risk_links" }

// CcfPoamItemEvidenceLink is the join table linking PoamItems to Evidence records.
type CcfPoamItemEvidenceLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_evidence_links_unique,unique" json:"poamItemId"`
	EvidenceID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_evidence_links_unique,unique" json:"evidenceId"`
}

func (CcfPoamItemEvidenceLink) TableName() string { return "ccf_poam_item_evidence_links" }

// CcfPoamItemControlLink is the join table linking PoamItems to Controls.
type CcfPoamItemControlLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_control_links_unique,unique" json:"poamItemId"`
	CatalogID  uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_control_links_unique,unique" json:"catalogId"`
	ControlID  string    `gorm:"type:text;not null;index:ccf_poam_item_control_links_unique,unique" json:"controlId"`
}

func (CcfPoamItemControlLink) TableName() string { return "ccf_poam_item_control_links" }

// CcfPoamItemFindingLink is the join table linking PoamItems to Findings.
type CcfPoamItemFindingLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_finding_links_unique,unique" json:"poamItemId"`
	FindingID  uuid.UUID `gorm:"type:uuid;not null;index:ccf_poam_item_finding_links_unique,unique" json:"findingId"`
}

func (CcfPoamItemFindingLink) TableName() string { return "ccf_poam_item_finding_links" }
