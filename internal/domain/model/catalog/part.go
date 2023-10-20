package catalog

import (
	"github.com/compliance-framework/configuration-service/internal/domain/model"
)

type Part struct {
	Uuid  model.Uuid       `json:"uuid"`
	Name  string           `json:"name"`
	Ns    string           `json:"ns"`
	Class string           `json:"class"`
	Title string           `json:"title"`
	Props []model.Property `json:"props"`
	Parts []Part           `json:"parts"`
	Links []model.Link     `json:"links"`
}
