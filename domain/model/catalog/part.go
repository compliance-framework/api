package catalog

import (
	model2 "github.com/compliance-framework/configuration-service/domain/model"
)

type Part struct {
	Uuid  model2.Uuid       `json:"uuid"`
	Name  string            `json:"name"`
	Ns    string            `json:"ns"`
	Class string            `json:"class"`
	Title string            `json:"title"`
	Props []model2.Property `json:"props"`
	Parts []Part            `json:"parts"`
	Links []model2.Link     `json:"links"`
}
