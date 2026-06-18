package suggestions

import (
	"errors"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type DashboardSuggestionEventType string

const (
	DashboardSuggestionEventTypeRunStarted        DashboardSuggestionEventType = "run_started"
	DashboardSuggestionEventTypeRunCompleted      DashboardSuggestionEventType = "run_completed"
	DashboardSuggestionEventTypeRunFailed         DashboardSuggestionEventType = "run_failed"
	DashboardSuggestionEventTypeSuggestionCreated DashboardSuggestionEventType = "suggestion_created"
	DashboardSuggestionEventTypeAccepted          DashboardSuggestionEventType = "accepted"
	DashboardSuggestionEventTypeRejected          DashboardSuggestionEventType = "rejected"
	DashboardSuggestionEventTypeSuperseded        DashboardSuggestionEventType = "superseded"
	DashboardSuggestionEventTypeEdited            DashboardSuggestionEventType = "edited"
)

type DashboardSuggestionEvent struct {
	relational.UUIDModel

	RunID        *uuid.UUID        `json:"runId" gorm:"type:uuid;index"`
	SuggestionID *uuid.UUID        `json:"suggestionId" gorm:"type:uuid;index"`
	EventType    string            `json:"eventType" gorm:"type:varchar(64);not null;index"`
	ActorUserID  *uuid.UUID        `json:"actorUserId" gorm:"type:uuid;index"`
	OccurredAt   time.Time         `json:"occurredAt" gorm:"not null;index"`
	Details      *string           `json:"details" gorm:"type:text"`
	Payload      datatypes.JSONMap `json:"payload" gorm:"type:jsonb"`
	Snapshot     datatypes.JSONMap `json:"snapshot" gorm:"type:jsonb"`

	Run        *DashboardSuggestionRun `json:"-" gorm:"foreignKey:RunID;references:ID"`
	Suggestion *DashboardSuggestion    `json:"-" gorm:"foreignKey:SuggestionID;references:ID"`
}

func (DashboardSuggestionEvent) TableName() string {
	return "dashboard_suggestion_events"
}

func (e *DashboardSuggestionEvent) BeforeCreate(_ *gorm.DB) error {
	if e.ID == nil {
		id := uuid.New()
		e.ID = &id
	}
	return nil
}

func (e *DashboardSuggestionEvent) BeforeUpdate(_ *gorm.DB) error {
	return errors.New("dashboard suggestion events are append-only")
}

func (e *DashboardSuggestionEvent) BeforeDelete(_ *gorm.DB) error {
	return errors.New("dashboard suggestion events are append-only")
}
