package handler

import (
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/store"
	"github.com/labstack/echo/v4"
	"net/http"
)

type PlanHandler struct {
	store store.PlanStore
}

func NewPlanHandler(s store.PlanStore) *PlanHandler {
	return &PlanHandler{store: s}
}

func (h *PlanHandler) Register(api *echo.Group) {
	api.POST("/plan", h.CreatePlan)
}

// CreatePlan godoc
// @Summary 		Create a plan
// @Description 	Creates a new plan in the system
// @Accept  		json
// @Produce  		json
// @Param   		plan body createPlanRequest true "Plan to add"
// @Success 		201 {object} planIdResponse
// @Failure 		401 {object} api.Error
// @Failure 		422 {object} api.Error
// @Failure 		500 {object} api.Error
// @Router 			/api/plan [post]
func (h *PlanHandler) CreatePlan(ctx echo.Context) error {
	p := domain.NewPlan()
	req := createPlanRequest{}
	if err := req.bind(ctx, p); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	id, err := h.store.CreatePlan(p)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, planIdResponse{
		Id: id.(string),
	})
}
