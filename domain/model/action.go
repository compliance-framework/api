package model

import (
	"time"
)

type Action struct {
	Uuid Uuid `json:"uuid"`

	ComprehensiveDetails

	Date                  time.Time `json:"date"`
	ResponsiblePartyUuids []string  `json:"responsiblePartyUuids"`
	System                string    `json:"system"`
	Type                  string    `json:"type"`
}
