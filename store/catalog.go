package store

import (
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
)

type CatalogStore interface {
	CreateCatalog(catalog *catalog.Catalog) (interface{}, error)
}
