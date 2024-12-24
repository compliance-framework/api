package domain

import (
	uuid "github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Uuid string

func NewUuid() Uuid {

	return Uuid(uuid.New().String())
}

func NewId() string {
	return primitive.NewObjectID().Hex()
}

func (u Uuid) String() string {
	return string(u)
}

type Selection struct {
	IncludeAll bool   `json:"includeAll" yaml:"includeAll"`
	Exclude    []Uuid `json:"exclude" yaml:"exclude"`
	Include    []Uuid `json:"include" yaml:"include"`
}
