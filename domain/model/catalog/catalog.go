package catalog

import (
	"github.com/compliance-framework/configuration-service/domain/model"
	"time"
)

type Catalog struct {
	Uuid  model.Uuid `json:"uuid"`
	Title string     `json:"title"` // Doesn't exist in OSCAL for some reason 🤷🏻

	Metadata model.Metadata `json:"metadata"`

	Params     []Parameter      `json:"params"`
	Controls   []model.Uuid     `json:"controlUuids"` // Reference to controls
	Groups     []model.Uuid     `json:"groupUuids"`   // Reference to groups
	BackMatter model.BackMatter `json:"backMatter"`
}

func NewCatalog(title string) Catalog {
	firstRevision := model.Revision{
		Title:        "Initial revision",
		Published:    time.Now(),
		LastModified: time.Now(),
		Version:      "1.0.0",
		OscalVersion: "1.1.0",
	}

	metadata := model.Metadata{
		Revisions: []model.Revision{firstRevision},
		Actions: []model.Action{
			{
				Uuid:  model.NewUuid(),
				Title: "Create",
			},
		},
	}
	return Catalog{
		Uuid:     model.NewUuid(),
		Title:    title,
		Metadata: metadata,
	}
}
