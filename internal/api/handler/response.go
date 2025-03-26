package handler

import (
	"github.com/compliance-framework/configuration-service/internal/domain"
)

type PlanResponse struct {
	domain.Plan
}

type GenericDataResponse[T any] struct {
	// Items from the list response
	Data T `json:"data" yaml:"data"`
}

type GenericDataListResponse[T any] struct {
	// Items from the list response
	Data []T `json:"data" yaml:"data"`
}

type SubjectResponse struct {
	domain.SubjectType
}
