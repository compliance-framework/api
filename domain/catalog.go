package domain

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Catalog struct {
	Uuid  Uuid   `json:"uuid" yaml:"uuid"`
	Title string `json:"title" yaml:"title"` // Doesn't exist in OSCAL for some reason 🤷🏻

	Metadata Metadata `json:"metadata" yaml:"metadata"`

	Params     []Parameter `json:"params" yaml:"params"`
	Controls   []Control   `json:"controlUuids" yaml:"controlUuids"` // Reference to controls. Controls is an array of objects in the database
	Groups     []Uuid      `json:"groupUuids" yaml:"groupUuids"`     // Reference to groups
	BackMatter BackMatter  `json:"backMatter" yaml:"backMatter"`
}

func NewCatalog(title string) Catalog {
	firstRevision := Revision{
		Title:        "Initial revision",
		Published:    time.Now(),
		LastModified: time.Now(),
		Version:      "1.0.0",
		OscalVersion: "1.1.0",
	}

	metadata := Metadata{
		Revisions: []Revision{firstRevision},
		Actions: []Action{
			{
				Id:    primitive.NewObjectID(),
				Title: "Create",
			},
		},
	}
	return Catalog{
		Uuid:     NewUuid(),
		Title:    title,
		Metadata: metadata,
	}
}
