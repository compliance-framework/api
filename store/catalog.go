package store

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
)

type CatalogStore interface {
	CreateControl(ctx context.Context, control *catalog.Control) (interface{}, error)
}
