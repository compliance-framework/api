package service

import (
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
	"github.com/compliance-framework/configuration-service/store"
)

type Control struct {
	store store.ControlStore
}

func NewControlService(store store.ControlStore) *Control {
	return &Control{}
}

func (c *Control) GetControl(id string) (catalog.Control, error) {
	return catalog.Control{}, nil
}

func (c *Control) CreateControl() (catalog.Control, error) {
	return catalog.Control{}, nil
}
