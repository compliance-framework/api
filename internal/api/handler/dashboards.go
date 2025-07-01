package handler

import (
	"gorm.io/gorm"
	//"net/http"
	//
	//"github.com/compliance-framework/configuration-service/internal/api"
	//"github.com/compliance-framework/configuration-service/internal/service"
	//"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// DashboardHandler handles CRUD operations for dashboards.
type DashboardHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func NewDashboardHandler(sugar *zap.SugaredLogger, db *gorm.DB) *DashboardHandler {
	return &DashboardHandler{
		sugar: sugar,
		db:    db,
	}
}

// Register registers the dashboard endpoints.
func (h *DashboardHandler) Register(api *echo.Group) {
	//api.GET("", h.List)
	//api.GET("/:id", h.Get)
	//api.POST("", h.Create)
}

//// Get godoc
////
////	@Summary		Get a dashboard
////	@Description	Retrieves a single dashboard by its unique ID.
////	@Tags			Dashboards
////	@Produce		json
////	@Param			id	path		string	true	"Dashboard ID"
////	@Success		200	{object}	GenericDataResponse[service.Dashboard]
////	@Failure		400	{object}	api.Error
////	@Failure		404	{object}	api.Error
////	@Failure		500	{object}	api.Error
////	@Router			/dashboard/{id} [get]
//func (h *DashboardHandler) Get(ctx echo.Context) error {
//	dashboard, err := h.service.Get(ctx.Request().Context(), uuid.MustParse(ctx.Param("id")))
//	if err != nil {
//		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
//	} else if dashboard == nil {
//		return ctx.JSON(http.StatusNotFound, api.NotFound())
//	}
//
//	return ctx.JSON(http.StatusOK, GenericDataResponse[service.Dashboard]{
//		Data: *dashboard,
//	})
//}
//
//// List godoc
////
////	@Summary		List dashboards
////	@Description	Retrieves all dashboards.
////	@Tags			Dashboards
////	@Produce		json
////	@Success		200	{object}	GenericDataListResponse[service.Dashboard]
////	@Failure		400	{object}	api.Error
////	@Failure		500	{object}	api.Error
////	@Router			/dashboard [get]
//func (h *DashboardHandler) List(c echo.Context) error {
//	results, err := h.service.List(c.Request().Context())
//	if err != nil {
//		return c.JSON(http.StatusInternalServerError, api.NewError(err))
//	}
//	return c.JSON(http.StatusOK, GenericDataListResponse[service.Dashboard]{
//		Data: *results,
//	})
//}
//
//// Create godoc
////
////	@Summary		Create a new dashboard
////	@Description	Creates a new dashboard.
////	@Tags			Dashboards
////	@Accept			json
////	@Produce		json
////	@Param			dashboard	body		createDashboardRequest	true	"Dashboard to add"
////	@Success		201			{object}	GenericDataResponse[service.Dashboard]
////	@Failure		400			{object}	api.Error
////	@Failure		422			{object}	api.Error
////	@Failure		500			{object}	api.Error
////	@Router			/dashboard [post]
//func (h *DashboardHandler) Create(ctx echo.Context) error {
//	// Initialize a new dashboard object.
//	p := &service.Dashboard{}
//
//	// Initialize a new createDashboardRequest object.
//	req := createDashboardRequest{}
//
//	// Bind the incoming request to the dashboard object.
//	if err := req.bind(ctx, p); err != nil {
//		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
//	}
//
//	// Attempt to create the dashboard.
//	_, err := h.service.Create(ctx.Request().Context(), p)
//	if err != nil {
//		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
//	}
//
//	// Return the created dashboard wrapped in a GenericDataResponse.
//	return ctx.JSON(http.StatusCreated, GenericDataResponse[service.Dashboard]{
//		Data: *p,
//	})
//}
