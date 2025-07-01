package service

import (
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/google/uuid"
	"time"
)

type Heartbeat struct {
	relational.UUIDModel

	UUID      uuid.UUID `gorm:"index"`
	CreatedAt time.Time `gorm:"index"`
}
