package domain

import (
	uuid "github.com/google/uuid"
)

type Uuid string

func NewUuid() Uuid {
	return Uuid(uuid.New().String())
}

type Selection struct {
	IncludeAll bool   `json:"includeAll"`
	Exclude    []Uuid `json:"exclude"`
	Include    []Uuid `json:"include"`
}
