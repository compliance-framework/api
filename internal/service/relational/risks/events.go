package risks

import (
	"errors"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type RiskEventType string

const (
	RiskEventTypeCreated         RiskEventType = "created"
	RiskEventTypeLastSeen        RiskEventType = "last_seen"
	RiskEventTypeStatusChange    RiskEventType = "status_changed"
	RiskEventTypeAccepted        RiskEventType = "accepted"
	RiskEventTypeReviewed        RiskEventType = "reviewed"
	RiskEventTypeScoreReassessed RiskEventType = "score_reassessed"
	RiskEventTypeEvidenceLink    RiskEventType = "evidence_linked"
	RiskEventTypeEvidenceUnlink  RiskEventType = "evidence_unlinked"
	RiskEventTypeControlLink     RiskEventType = "control_linked"
	RiskEventTypeControlUnlink   RiskEventType = "control_unlinked"
	RiskEventTypeComponentLink   RiskEventType = "component_linked"
	RiskEventTypeComponentUnlink RiskEventType = "component_unlinked"
	RiskEventTypeSubjectLink     RiskEventType = "subject_linked"
)

type RiskEvent struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`

	RiskID       uuid.UUID         `json:"riskId" gorm:"type:uuid;not null;index"`
	EventType    string            `json:"eventType" gorm:"type:varchar(64);not null;index"`
	ActorUserID  *uuid.UUID        `json:"actorUserId" gorm:"type:uuid;index"`
	OccurredAt   time.Time         `json:"occurredAt" gorm:"not null;index"`
	Details      *string           `json:"details" gorm:"type:text"`
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

func BuildRiskEventDetails(eventType string, payload datatypes.JSONMap, occurredAt time.Time) string {
	switch eventType {
	case string(RiskEventTypeCreated):
		if status := payloadString(payload, "status"); status != "" {
			return fmt.Sprintf("Risk was created with status %s.", status)
		}
		return "Risk was created."
	case string(RiskEventTypeLastSeen):
		lastSeen := payloadTime(payload, "newLastSeen", "new_last_seen")
		if lastSeen.IsZero() {
			lastSeen = occurredAt
		}
		return fmt.Sprintf("This risk was last seen on %s.", lastSeen.UTC().Format(time.RFC3339))
	case string(RiskEventTypeStatusChange):
		from := payloadString(payload, "from")
		to := payloadString(payload, "to")
		if from != "" && to != "" {
			return fmt.Sprintf("Risk status changed from %s to %s.", from, to)
		}
		return "Risk status changed."
	case string(RiskEventTypeAccepted):
		if justification := payloadString(payload, "justification"); justification != "" {
			return fmt.Sprintf("Risk was accepted. Justification: %s", justification)
		}
		return "Risk was accepted."
	case string(RiskEventTypeReviewed):
		if decision := payloadString(payload, "decision"); decision != "" {
			return fmt.Sprintf("Risk review decision recorded: %s.", decision)
		}
		return "Risk review was recorded."
	case string(RiskEventTypeScoreReassessed):
		fromLikelihood := payloadString(payload, "fromLikelihood", "from_likelihood")
		fromImpact := payloadString(payload, "fromImpact", "from_impact")
		toLikelihood := payloadString(payload, "toLikelihood", "to_likelihood")
		toImpact := payloadString(payload, "toImpact", "to_impact")
		if fromLikelihood != "" && fromImpact != "" && toLikelihood != "" && toImpact != "" {
			return fmt.Sprintf("Risk score was reassessed from likelihood=%s impact=%s to likelihood=%s impact=%s.", fromLikelihood, fromImpact, toLikelihood, toImpact)
		}
		return "Risk score was reassessed."
	case string(RiskEventTypeEvidenceLink):
		if evidenceID := payloadString(payload, "evidenceId", "evidence_id"); evidenceID != "" {
			return fmt.Sprintf("Evidence %s was linked to this risk.", evidenceID)
		}
		return "Evidence was linked to this risk."
	case string(RiskEventTypeEvidenceUnlink):
		if evidenceID := payloadString(payload, "evidenceId", "evidence_id"); evidenceID != "" {
			return fmt.Sprintf("Evidence %s was unlinked from this risk.", evidenceID)
		}
		return "Evidence was unlinked from this risk."
	case string(RiskEventTypeControlLink):
		catalogID := payloadString(payload, "catalogId", "catalog_id")
		controlID := payloadString(payload, "controlId", "control_id")
		if catalogID != "" && controlID != "" {
			return fmt.Sprintf("Control %s from catalog %s was linked to this risk.", controlID, catalogID)
		}
		if controlID != "" {
			return fmt.Sprintf("Control %s was linked to this risk.", controlID)
		}
		return "A control was linked to this risk."
	case string(RiskEventTypeControlUnlink):
		catalogID := payloadString(payload, "catalogId", "catalog_id")
		controlID := payloadString(payload, "controlId", "control_id")
		if catalogID != "" && controlID != "" {
			return fmt.Sprintf("Control %s from catalog %s was unlinked from this risk.", controlID, catalogID)
		}
		if controlID != "" {
			return fmt.Sprintf("Control %s was unlinked from this risk.", controlID)
		}
		return "A control was unlinked from this risk."
	case string(RiskEventTypeComponentLink):
		if componentID := payloadString(payload, "componentId", "component_id"); componentID != "" {
			return fmt.Sprintf("Component %s was linked to this risk.", componentID)
		}
		return "A component was linked to this risk."
	case string(RiskEventTypeComponentUnlink):
		if componentID := payloadString(payload, "componentId", "component_id"); componentID != "" {
			return fmt.Sprintf("Component %s was unlinked from this risk.", componentID)
		}
		return "A component was unlinked from this risk."
	case string(RiskEventTypeSubjectLink):
		if subjectID := payloadString(payload, "subjectId", "subject_id"); subjectID != "" {
			return fmt.Sprintf("Subject %s was linked to this risk.", subjectID)
		}
		return "A subject was linked to this risk."
	default:
		return fmt.Sprintf("Risk event recorded: %s.", eventType)
	}
}

func payloadString(payload datatypes.JSONMap, keys ...string) string {
	if payload == nil {
		return ""
	}
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok || raw == nil {
			continue
		}
		switch value := raw.(type) {
		case string:
			if value != "" {
				return value
			}
		case fmt.Stringer:
			text := value.String()
			if text != "" {
				return text
			}
		}
	}
	return ""
}

func payloadTime(payload datatypes.JSONMap, keys ...string) time.Time {
	if payload == nil {
		return time.Time{}
	}
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok || raw == nil {
			continue
		}
		switch value := raw.(type) {
		case time.Time:
			return value
		case string:
			if parsed, err := time.Parse(time.RFC3339, value); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}
