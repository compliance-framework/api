package service

import (
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"gorm.io/datatypes"
)

type Dashboard struct {
	relational.UUIDModel

	Name   string                                 `json:"name" yaml:"name"`
	Filter datatypes.JSONType[labelfilter.Filter] `json:"filter" yaml:"filter"`
}
