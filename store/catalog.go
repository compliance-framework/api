package store

import (
	"github.com/compliance-framework/configuration-service/domain"
)

type CatalogStore interface {
	CreateCatalog(catalog *domain.Catalog) (interface{}, error)
}
