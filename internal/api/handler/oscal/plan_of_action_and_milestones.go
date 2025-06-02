package oscal

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/defenseunicorns/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

type PlanOfActionAndMilestonesHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewPlanOfActionAndMilestonesHandler(sugar *zap.SugaredLogger, db *gorm.DB) *PlanOfActionAndMilestonesHandler {
	return &PlanOfActionAndMilestonesHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *PlanOfActionAndMilestonesHandler) Register(api *echo.Group) {
	api.GET("/poam", h.List)
	api.GET("/poam/:uuid", h.Get)
	api.GET("/poam/:uuid/full", h.Full)
	api.GET("/poam/:uuid/observations", h.GetObservations)
	api.GET("/poam/:uuid/risks", h.GetRisks)
	api.GET("/poam/:uuid/findings", h.GetFindings)
	api.GET("/poam/:uuid/poam-items", h.GetPoamItems)
}

func (h *PlanOfActionAndMilestonesHandler) List(ctx echo.Context) error {
	type responsePlanOfActionAndMilestones struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	var poams []relational.PlanOfActionAndMilestones
	if err := h.db.Find(&poams).Error; err != nil {
		h.sugar.Errorw("failed to list poams", "error", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to list poams",
		})
	}

	response := make([]responsePlanOfActionAndMilestones, len(poams))
	for i, poam := range poams {
		response[i] = responsePlanOfActionAndMilestones{
			UUID:     poam.UUID,
			Metadata: *poam.Metadata.MarshalOscal(),
		}
	}

	return ctx.JSON(http.StatusOK, response)
}

func (h *PlanOfActionAndMilestonesHandler) Get(ctx echo.Context) error {
	type responsePlanOfActionAndMilestones struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	uuidStr := ctx.Param("uuid")
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		h.sugar.Errorw("invalid uuid", "error", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid uuid",
		})
	}

	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "uuid = ?", uuid).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get poam",
		})
	}

	response := responsePlanOfActionAndMilestones{
		UUID:     poam.UUID,
		Metadata: *poam.Metadata.MarshalOscal(),
	}

	return ctx.JSON(http.StatusOK, response)
}

func (h *PlanOfActionAndMilestonesHandler) Full(ctx echo.Context) error {
	uuidStr := ctx.Param("uuid")
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		h.sugar.Errorw("invalid uuid", "error", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid uuid",
		})
	}

	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "uuid = ?", uuid).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get poam",
		})
	}

	return ctx.JSON(http.StatusOK, poam.MarshalOscal())
}

func (h *PlanOfActionAndMilestonesHandler) GetObservations(ctx echo.Context) error {
	uuidStr := ctx.Param("uuid")
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		h.sugar.Errorw("invalid uuid", "error", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid uuid",
		})
	}

	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "uuid = ?", uuid).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get poam",
		})
	}

	if poam.Observations == nil {
		return ctx.JSON(http.StatusOK, []relational.Observation{})
	}

	return ctx.JSON(http.StatusOK, poam.Observations)
}

func (h *PlanOfActionAndMilestonesHandler) GetRisks(ctx echo.Context) error {
	uuidStr := ctx.Param("uuid")
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		h.sugar.Errorw("invalid uuid", "error", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid uuid",
		})
	}

	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "uuid = ?", uuid).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get poam",
		})
	}

	if poam.Risks == nil {
		return ctx.JSON(http.StatusOK, []relational.Risk{})
	}

	return ctx.JSON(http.StatusOK, poam.Risks)
}

func (h *PlanOfActionAndMilestonesHandler) GetFindings(ctx echo.Context) error {
	uuidStr := ctx.Param("uuid")
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		h.sugar.Errorw("invalid uuid", "error", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid uuid",
		})
	}

	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "uuid = ?", uuid).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get poam",
		})
	}

	if poam.Findings == nil {
		return ctx.JSON(http.StatusOK, []relational.Finding{})
	}

	return ctx.JSON(http.StatusOK, poam.Findings)
}

func (h *PlanOfActionAndMilestonesHandler) GetPoamItems(ctx echo.Context) error {
	uuidStr := ctx.Param("uuid")
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		h.sugar.Errorw("invalid uuid", "error", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid uuid",
		})
	}

	var poam relational.PlanOfActionAndMilestones
	if err := h.db.First(&poam, "uuid = ?", uuid).Error; err != nil {
		h.sugar.Errorw("failed to get poam", "error", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get poam",
		})
	}

	return ctx.JSON(http.StatusOK, poam.PoamItems)
}
