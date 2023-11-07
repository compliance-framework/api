package handler

import (
	"net/http"

	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type SSPHandler struct {
	service *service.SSPService
}

func NewSSPHandler(sspService *service.SSPService) *SSPHandler {
	return &SSPHandler{service: sspService}
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
// @Success 		201 {object} idResponse
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

	return ctx.JSON(http.StatusCreated, idResponse{
		Id: id,
	})
} 

// GetSSP godoc
// @Summary     Get an SSP by ID
// @Description Get an SSP by its ID
// @Tags        SSP
// @Accept      json
// @Produce     json
// @Param       id path string true "SSP ID"
// @Success     200 {object} domain.SystemSecurityPlan
// @Failure     404 {object} api.Error
// @Failure     500 {object} api.Error
// @Router      /api/ssp/{id} [get]
func (h *SSPHandler) GetSSP(ctx echo.Context) error {
	id := ctx.Param("id")

	ssp, err := h.service.GetByID(id)
	if err != nil {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, ssp)
}

// UpdateSSP godoc
// @Summary     Update an SSP
// @Description Update an SSP with the given ID
// @Tags        SSP
// @Accept      json
// @Produce     json
// @Param       id path string true "SSP ID"
// @Param       SSP body UpdateSSPRequest true "SSP to update"
// @Success     200 {object} domain.SystemSecurityPlan
// @Failure     400 {object} api.Error
// @Failure     404 {object} api.Error
// @Failure     500 {object} api.Error
// @Router      /api/ssp/{id} [put]
func (h *SSPHandler) UpdateSSP(ctx echo.Context) error {
	id := ctx.Param("id")
	var ssp domain.SystemSecurityPlan
	req := updateSSPRequest{}

	if err := req.bind(ctx, &ssp); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	updatedSSP, err := h.service.Update(id, &ssp)
	if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, updatedSSP)
}

// DeleteSSP godoc
// @Summary     Delete an SSP
// @Description Delete an SSP with the given ID
// @Tags        SSP
// @Accept      json
// @Produce     json
// @Param       id path string true "SSP ID"
// @Success     204 {object} string
// @Failure     404 {object} api.Error
// @Failure     500 {object} api.Error
// @Router      /api/ssp/{id} [delete]
func (h *SSPHandler) DeleteSSP(ctx echo.Context) error {
	id := ctx.Param("id")

	if err := h.service.Delete(id); err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}
