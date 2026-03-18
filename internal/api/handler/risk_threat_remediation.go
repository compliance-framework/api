package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	svc "github.com/compliance-framework/api/internal/service"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func (h *RiskHandler) ListThreatRefsForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.ListThreatRefs(ctx)
}

func (h *RiskHandler) ListThreatRefs(ctx echo.Context) error {
	return h.withRiskListContext(ctx, func(riskID uuid.UUID, pagination *svc.PaginationParams) error {
		rows, total, err := h.riskService.ListThreatRefs(riskID, pagination.Limit, pagination.Offset)
		if err != nil {
			return h.internalServerError(ctx, "failed to list risk threat references", err)
		}

		resp := make([]threatIDResponse, 0, len(rows))
		for _, row := range rows {
			if row.ID == nil {
				continue
			}
			resp = append(resp, threatIDResponse{
				ID:     *row.ID,
				System: row.System,
				RefID:  row.ExternalID,
				Title:  row.Title,
				URL:    row.URL,
			})
		}

		return ctx.JSON(http.StatusOK, svc.NewListResponse(resp, total, pagination.Page, pagination.Limit))
	})
}

func (h *RiskHandler) GetThreatRefForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.GetThreatRef(ctx)
}

func (h *RiskHandler) GetThreatRef(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	threatRefID, err := parsePathUUID(ctx, "threatRefId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	row, err := h.riskService.GetThreatRef(riskID, threatRefID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("threat reference not found")))
		}
		return h.internalServerError(ctx, "failed to get risk threat reference", err)
	}

	if row.ID == nil {
		return h.internalServerError(ctx, "threat reference is missing id", fmt.Errorf("threat reference missing id"))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[threatIDResponse]{Data: threatIDResponse{
		ID:     *row.ID,
		System: row.System,
		RefID:  row.ExternalID,
		Title:  row.Title,
		URL:    row.URL,
	}})
}

func (h *RiskHandler) AddThreatRefForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.AddThreatRef(ctx)
}

func (h *RiskHandler) AddThreatRef(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req threatIDRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		row, err := h.riskService.AddThreatRef(riskID, riskrel.RiskThreatRefInput{
			System:     req.System,
			ExternalID: req.ID,
			Title:      req.Title,
			URL:        req.URL,
		}, actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
			}
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to add threat reference", err)
		}
		if row.ID == nil {
			return h.internalServerError(ctx, "threat reference is missing id", fmt.Errorf("threat reference missing id"))
		}
		return ctx.JSON(http.StatusCreated, GenericDataResponse[threatIDResponse]{Data: threatIDResponse{
			ID:     *row.ID,
			System: row.System,
			RefID:  row.ExternalID,
			Title:  row.Title,
			URL:    row.URL,
		}})
	})
}

func (h *RiskHandler) UpdateThreatRefForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.UpdateThreatRef(ctx)
}

func (h *RiskHandler) UpdateThreatRef(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	threatRefID, err := parsePathUUID(ctx, "threatRefId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req threatIDRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		row, err := h.riskService.UpdateThreatRef(riskID, threatRefID, riskrel.RiskThreatRefInput{
			System:     req.System,
			ExternalID: req.ID,
			Title:      req.Title,
			URL:        req.URL,
		}, actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("threat reference not found")))
			}
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to update threat reference", err)
		}
		if row.ID == nil {
			return h.internalServerError(ctx, "threat reference is missing id", fmt.Errorf("threat reference missing id"))
		}
		return ctx.JSON(http.StatusOK, GenericDataResponse[threatIDResponse]{Data: threatIDResponse{
			ID:     *row.ID,
			System: row.System,
			RefID:  row.ExternalID,
			Title:  row.Title,
			URL:    row.URL,
		}})
	})
}

func (h *RiskHandler) DeleteThreatRefForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.DeleteThreatRef(ctx)
}

func (h *RiskHandler) DeleteThreatRef(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	threatRefID, err := parsePathUUID(ctx, "threatRefId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		deleted, err := h.riskService.DeleteThreatRef(riskID, threatRefID, actorID)
		if err != nil {
			return h.internalServerError(ctx, "failed to delete threat reference", err)
		}
		if !deleted {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("threat reference not found")))
		}
		return ctx.NoContent(http.StatusNoContent)
	})
}

func (h *RiskHandler) GetRemediationTemplateForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.GetRemediationTemplate(ctx)
}

func (h *RiskHandler) GetRemediationTemplate(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	row, err := h.riskService.GetRemediationTemplate(riskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("remediation template not found")))
		}
		return h.internalServerError(ctx, "failed to get remediation template", err)
	}
	if row.ID == nil {
		return h.internalServerError(ctx, "remediation template is missing id", fmt.Errorf("remediation template missing id"))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[remediationTemplateResponse]{Data: mapRemediationTemplateResponse(*row)})
}

func (h *RiskHandler) CreateRemediationTemplateForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.CreateRemediationTemplate(ctx)
}

func (h *RiskHandler) CreateRemediationTemplate(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req remediationTemplateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		row, err := h.riskService.CreateRemediationTemplate(riskID, toRemediation(&req), actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
			}
			if errors.Is(err, riskrel.ErrRemediationTemplateAlreadyExists) {
				return ctx.JSON(http.StatusConflict, api.NewError(err))
			}
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to create remediation template", err)
		}

		return ctx.JSON(http.StatusCreated, GenericDataResponse[remediationTemplateResponse]{Data: mapRemediationTemplateResponse(*row)})
	})
}

func (h *RiskHandler) UpsertRemediationTemplateForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.UpsertRemediationTemplate(ctx)
}

func (h *RiskHandler) UpsertRemediationTemplate(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var req remediationTemplateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		row, err := h.riskService.UpsertRemediationTemplate(riskID, toRemediation(&req), actorID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
			}
			if riskrel.IsValidationError(err) {
				return ctx.JSON(http.StatusBadRequest, api.NewError(err))
			}
			return h.internalServerError(ctx, "failed to upsert remediation template", err)
		}

		return ctx.JSON(http.StatusOK, GenericDataResponse[remediationTemplateResponse]{Data: mapRemediationTemplateResponse(*row)})
	})
}

func (h *RiskHandler) DeleteRemediationTemplateForSSP(ctx echo.Context) error {
	sspID, err := parsePathUUID(ctx, "sspId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.ensureRiskBelongsToSSP(riskID, sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
		}
		return h.internalServerError(ctx, "failed to validate scoped risk", err)
	}
	return h.DeleteRemediationTemplate(ctx)
}

func (h *RiskHandler) DeleteRemediationTemplate(ctx echo.Context) error {
	riskID, err := parsePathUUID(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return h.withActorUserID(ctx, func(actorID *uuid.UUID) error {
		deleted, err := h.riskService.DeleteRemediationTemplate(riskID, actorID)
		if err != nil {
			return h.internalServerError(ctx, "failed to delete remediation template", err)
		}
		if !deleted {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("remediation template not found")))
		}
		return ctx.NoContent(http.StatusNoContent)
	})
}

func mapRemediationTemplateResponse(row riskrel.RiskRemediationTemplate) remediationTemplateResponse {
	resp := remediationTemplateResponse{
		Title:       row.Title,
		Description: row.Description,
		Tasks:       make([]remediationTaskResponse, 0, len(row.Tasks)),
	}
	if row.ID != nil {
		resp.ID = *row.ID
	}
	for _, task := range row.Tasks {
		if task.ID == nil {
			continue
		}
		resp.Tasks = append(resp.Tasks, remediationTaskResponse{
			ID:         *task.ID,
			Title:      task.Title,
			OrderIndex: task.OrderIndex,
		})
	}
	return resp
}
