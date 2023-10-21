package service

import (
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
	"github.com/compliance-framework/configuration-service/store"
)

type Catalog struct {
	store store.CatalogStore
}

func NewCatalogService(store store.CatalogStore) *Catalog {
	return &Catalog{}
}

func (c *Catalog) GetControl(id string) (catalog.Control, error) {
	return catalog.Control{}, nil
}

func (c *Catalog) CreateControl() (catalog.Control, error) {
	return catalog.Control{}, nil
}
