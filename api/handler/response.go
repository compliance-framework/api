package handler

import "github.com/compliance-framework/configuration-service/converters/labelfilter"

// idResponse is a struct that holds the ID of a model.
// swagger:model
type idResponse struct {
	// The unique identifier of the plan.
	// Required: true
	// Example: "456def"
	Id string `json:"id" yaml:"id"`
}

type PlanResponse struct {
	Id     string             `json:"id" yaml:"id"`
	Title  string             `json:"title" yaml:"title"`
	Filter labelfilter.Filter `json:"filter" yaml:"filter"`
}

// catalogIdResponse is a struct that holds the ID of a catalog.
// swagger:model
type catalogIdResponse struct {
	// The unique identifier of the catalog.
	// Required: true
	// Example: "123abc"
	Id string `json:"id" yaml:"id"`
}

type GenericDataResponse[T any] struct {
	// Items from the list response
	Data T `json:"data" yaml:"data"`
}

type GenericDataListResponse[T any] struct {
	// Items from the list response
	Data []T `json:"data" yaml:"data"`
}
