package models

import (
	"fmt"

	_ "github.com/compliance-framework/configuration-service/internal/models/oscal/v1_1"
	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

func Get(name string) (*schema.Object, error) {
	model, ok := schema.Registry[name]
	if !ok {
		return nil, fmt.Errorf("driver not found")
	}
	return &model, nil
}
