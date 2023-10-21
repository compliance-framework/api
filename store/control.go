package store

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
)

type ControlStore interface {
	Create(ctx context.Context, control *catalog.Control) (interface{}, error)
}
