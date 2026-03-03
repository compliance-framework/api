package risks

import (
	"errors"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type RiskEventType string

const (
	RiskEventTypeCreated        RiskEventType = "created"
	RiskEventTypeLastSeen       RiskEventType = "last_seen"
	RiskEventTypeStatusChange   RiskEventType = "status_changed"
	RiskEventTypeAccepted       RiskEventType = "accepted"
	RiskEventTypeReviewed       RiskEventType = "reviewed"
	RiskEventTypeEvidenceLink   RiskEventType = "evidence_linked"
	RiskEventTypeEvidenceUnlink RiskEventType = "evidence_unlinked"
	RiskEventTypeControlLink    RiskEventType = "control_linked"
	RiskEventTypeComponentLink  RiskEventType = "component_linked"
	RiskEventTypeSubjectLink    RiskEventType = "subject_linked"
)

type RiskEvent struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`

	RiskID       uuid.UUID         `json:"riskId" gorm:"type:uuid;not null;index"`
	EventType    string            `json:"eventType" gorm:"type:varchar(64);not null;index"`
	ActorUserID  *uuid.UUID        `json:"actorUserId" gorm:"type:uuid;index"`
	OccurredAt   time.Time         `json:"occurredAt" gorm:"not null;index"`
	Payload      datatypes.JSONMap `json:"payload" gorm:"type:jsonb"`
	RiskSnapshot datatypes.JSONMap `json:"riskSnapshot" gorm:"type:jsonb"`

	Risk *Risk `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskEvent) TableName() string {
	return "risk_events"
}

func (e *RiskEvent) BeforeCreate(_ *gorm.DB) error {
	if e.ID == nil {
		id := uuid.New()
		e.ID = &id
	}
	return nil
}

func (e *RiskEvent) BeforeUpdate(_ *gorm.DB) error {
	return errors.New("risk events are append-only")
}

func (e *RiskEvent) BeforeDelete(_ *gorm.DB) error {
	return errors.New("risk events are append-only")
}
