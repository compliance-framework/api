package risks

import (
	"time"

	"github.com/google/uuid"
)

type RiskEvidenceLink struct {
	RiskID      uuid.UUID  `json:"riskId" gorm:"type:uuid;primaryKey"`
	EvidenceID  uuid.UUID  `json:"evidenceId" gorm:"type:uuid;primaryKey;index"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedByID *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
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
}

func (RiskControlLink) TableName() string {
	return "risk_control_links"
}

type RiskComponentLink struct {
	RiskID      uuid.UUID  `json:"riskId" gorm:"type:uuid;primaryKey"`
	ComponentID uuid.UUID  `json:"componentId" gorm:"type:uuid;primaryKey;index"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedByID *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
}

func (RiskComponentLink) TableName() string {
	return "risk_component_links"
}

type RiskSubjectLink struct {
	RiskID      uuid.UUID  `json:"riskId" gorm:"type:uuid;primaryKey"`
	SubjectID   uuid.UUID  `json:"subjectId" gorm:"type:uuid;primaryKey;index"`
	CreatedAt   time.Time  `json:"createdAt"`
	CreatedByID *uuid.UUID `json:"createdById" gorm:"type:uuid;index"`
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
}

func (RiskOwnerAssignment) TableName() string {
	return "risk_owner_assignments"
}
