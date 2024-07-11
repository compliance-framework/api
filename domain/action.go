package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Action struct {
	Id primitive.ObjectID `json:"id" yaml:"id"`

	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	Date                  time.Time            `json:"date" yaml:"date"`
	ResponsiblePartyUuids []primitive.ObjectID `json:"responsiblePartyUuids" yaml:"responsiblePartyUuids"`
	System                string               `json:"system" yaml:"system"`
	Type                  string               `json:"type" yaml:"type"`
}
