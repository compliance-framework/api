package handler

import (
	"github.com/compliance-framework/configuration-service/domain/service"
	"github.com/labstack/echo/v4"
	"net/http"
)

type ControlHandler struct {
	service *service.Control
}

func NewControlHandler(s *service.Control) *ControlHandler {
	return &ControlHandler{service: s}
}

func (h *ControlHandler) Register(api *echo.Group) {
	api.GET("/controls/:id", h.GetControl)
}

func (h *ControlHandler) GetControl(c echo.Context) error {
	id := c.Param("id")
	obj, err := h.service.GetControl(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, obj)
}
