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
	api.POST("/systemsecurityplan", h.CreateSSP)
}

// CreateCatalog godoc
// @Summary 		Create a catalog
// @Description 	Create a catalog with the given title
// @Tags 			Catalog
// @Accept  		json
// @Produce  		json
// @Param   		catalog body createCatalogRequest true "Catalog to add"
// @Success 		201 {object} catalogIdResponse
// @Failure 		401 {object} api.Error
// @Failure 		422 {object} api.Error
// @Failure 		500 {object} api.Error
// @Router 			/api/catalog [post]
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