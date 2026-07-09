package risks

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
)

type RiskEvidenceLink struct {
	RiskID uuid.UUID `json:"riskId" gorm:"type:uuid;primaryKey"`
	// EvidenceID stores the evidence stream UUID (evidences.uuid), not a single evidence row ID.
	EvidenceID  uuid.UUID  `json:"evidenceId" gorm:"type:uuid;primaryKey;index"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedByID *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
	Risk        *Risk      `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskEvidenceLink) TableName() string {
	return "risk_evidence_links"
}

type RiskControlLink struct {
	RiskID      uuid.UUID  `json:"riskId" gorm:"type:uuid;primaryKey"`
	CatalogID   uuid.UUID  `json:"catalogId" gorm:"type:uuid;primaryKey;index"`
	ControlID   string     `json:"controlId" gorm:"type:text;primaryKey;index"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedByID *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
	Risk        *Risk      `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskControlLink) TableName() string {
	return "risk_control_links"
}

type RiskComponentLink struct {
	RiskID      uuid.UUID  `json:"riskId" gorm:"type:uuid;primaryKey"`
	ComponentID uuid.UUID  `json:"componentId" gorm:"type:uuid;primaryKey;index"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedByID *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
	Risk        *Risk      `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskComponentLink) TableName() string {
	return "risk_component_links"
}

type RiskResponsibilityLink struct {
	RiskID uuid.UUID `json:"riskId" gorm:"type:uuid;primaryKey"`
	// ResponsibilityUUID is the upstream ControlImplementationResponsibility uuid
	// (BCH-1340) — resolved via the filter_responsibilities -> ssp_leverage_links arm in
	// risk_evidence_worker.go, not a local catalog control.
	ResponsibilityUUID uuid.UUID  `json:"responsibilityUuid" gorm:"type:uuid;primaryKey;index"`
	CreatedAt          time.Time  `json:"createdAt"`
	CreatedByID        *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
	Risk               *Risk      `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskResponsibilityLink) TableName() string {
	return "risk_responsibility_links"
}

type RiskSubjectLink struct {
	RiskID      uuid.UUID  `json:"riskId" gorm:"type:uuid;primaryKey"`
	SubjectID   uuid.UUID  `json:"subjectId" gorm:"type:uuid;primaryKey;index"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedByID *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
	Risk        *Risk      `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskSubjectLink) TableName() string {
	return "risk_subject_links"
}

type RiskOwnerAssignment struct {
	RiskID    uuid.UUID `json:"riskId" gorm:"type:uuid;primaryKey"`
	OwnerKind string    `json:"ownerKind" gorm:"type:varchar(16);primaryKey"`
	OwnerRef  string    `json:"ownerRef" gorm:"type:text;primaryKey"`
	IsPrimary bool      `json:"isPrimary" gorm:"not null;default:false;index"`
	CreatedAt time.Time `json:"createdAt"`
	Risk      *Risk     `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskOwnerAssignment) TableName() string {
	return "risk_owner_assignments"
}

type RiskThreatRef struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	RiskID uuid.UUID `json:"riskId" gorm:"type:uuid;not null;index;uniqueIndex:idx_risk_threat_refs_unique,priority:1"`

	System     string  `json:"system" gorm:"type:text;not null;uniqueIndex:idx_risk_threat_refs_unique,priority:2"`
	ExternalID string  `json:"externalId" gorm:"column:external_id;type:text;not null;uniqueIndex:idx_risk_threat_refs_unique,priority:3"`
	Title      string  `json:"title" gorm:"type:text;not null"`
	URL        *string `json:"url" gorm:"type:text"`

	Risk *Risk `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskThreatRef) TableName() string {
	return "risk_threat_refs"
}

type RiskRemediationTemplate struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	RiskID uuid.UUID `json:"riskId" gorm:"type:uuid;not null;uniqueIndex"`

	Title       string  `json:"title" gorm:"type:text;not null"`
	Description *string `json:"description" gorm:"type:text"`

	Tasks []RiskRemediationTask `json:"tasks,omitempty" gorm:"foreignKey:RiskRemediationTemplateID;constraint:OnDelete:CASCADE"`
	Risk  *Risk                 `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskRemediationTemplate) TableName() string {
	return "risk_remediation_templates"
}

type RiskRemediationTask struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	RiskRemediationTemplateID uuid.UUID `json:"riskRemediationTemplateId" gorm:"type:uuid;not null;index;uniqueIndex:idx_risk_remediation_tasks_unique_order,priority:1"`
	Title                     string    `json:"title" gorm:"type:text;not null"`
	OrderIndex                int       `json:"orderIndex" gorm:"not null;uniqueIndex:idx_risk_remediation_tasks_unique_order,priority:2"`

	RemediationTemplate *RiskRemediationTemplate `json:"-" gorm:"foreignKey:RiskRemediationTemplateID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskRemediationTask) TableName() string {
	return "risk_remediation_tasks"
}
