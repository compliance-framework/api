package handler

type GenericDataResponse[T any] struct {
	// Wrapped response data
	Data T `json:"data" yaml:"data"`
}

type GenericDataListResponse[T any] struct {
	// Items from the list response
	Data []T `json:"data" yaml:"data"`
}
