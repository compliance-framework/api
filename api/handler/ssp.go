package handler

import (
	service "command-line-arguments/Users/eb/workspace/compliance-framework/configuration-service/service/ssp.go"
	"net/http"

	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/labstack/echo/v4"
)

type SSPHandler struct {
	service *service.SSPService
}

func NewSSPHandler() *SSPHandler {
	return &SSPHandler{}
}

func (h *SSPHandler) Register(api *echo.Group) {
	api.POST("/ssp", h.CreateSSP)
}

// CreateSSP godoc
// @Summary 		Create a SSP
// @Description 	Create a SSP with the given title
// @Tags 			SSP
// @Accept  		json
// @Produce  		json
// @Param   		SSP body CreateSSPRequest true "SSP to add"
// @Success 		201 {object} sspIdResponse
// @Failure 		401 {object} api.Error
// @Failure 		422 {object} api.Error
// @Failure 		500 {object} api.Error
// @Router 			/api/ssp [post]
func (h *SSPHandler) CreateSSP(ctx echo.Context) error {
	var ssp domain.SystemSecurityPlan
	req := createSSPRequest{}

	if err := req.bind(ctx, &ssp); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	id, err := h.service.Create(&ssp)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, sspIdResponse{
		Id: id.(string),
	})
}
