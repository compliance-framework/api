package model

import (
	"time"
)

type Action struct {
	Uuid Uuid `json:"uuid"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Date                  time.Time `json:"date"`
	ResponsiblePartyUuids []string  `json:"responsiblePartyUuids"`
	System                string    `json:"system"`
	Type                  string    `json:"type"`
}
