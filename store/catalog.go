package store

import (
	"github.com/compliance-framework/configuration-service/domain"
)

type CatalogStore interface {
	CreateCatalog(catalog *domain.Catalog) (interface{}, error)
	GetCatalog(id string) (*domain.Catalog, error)
	UpdateCatalog(id string, catalog *domain.Catalog) error
	DeleteCatalog(id string) error
	CreateControl(catalogId string, control *domain.Control) (interface{}, error)
	GetControl(catalogId string, controlId string) (*domain.Control, error)
	UpdateControl(catalogId string, controlId string, control *domain.Control) (*domain.Catalog, error)
}
