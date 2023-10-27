package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Action struct {
	Id primitive.ObjectID `json:"id"`

	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Date                  time.Time            `json:"date"`
	ResponsiblePartyUuids []primitive.ObjectID `json:"responsiblePartyUuids"`
	System                string               `json:"system"`
	Type                  string               `json:"type"`
}
