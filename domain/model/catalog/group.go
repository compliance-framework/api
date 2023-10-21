package catalog

import (
	"github.com/compliance-framework/configuration-service/domain/model"
)

type Group struct {
	Uuid model.Uuid `json:"uuid"`

	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Props       []model.Property `json:"props,omitempty"`
	Links       []model.Link     `json:"links,omitempty"`
	Remarks     string           `json:"remarks,omitempty"`

	Class  string       `json:"class"`
	Params []Parameter  `json:"params"`
	Groups []model.Uuid `json:"groups"`
}
