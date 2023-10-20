package service

import "github.com/compliance-framework/configuration-service/internal/domain/model/catalog"

type Control struct{}

func NewControlService() *Control {
	return &Control{}
}

func (c *Control) GetControl(id string) (catalog.Control, error) {
	return catalog.Control{}, nil
}

func (c *Control) CreateControl() (catalog.Control, error) {
	return catalog.Control{}, nil
}
