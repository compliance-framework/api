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

// ListThreatRefsForSSP godoc
//
//	@Summary		List risk threat references for SSP
//	@Description	Lists threat references linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[threatIDResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/threat-ids [get]
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

// ListThreatRefs godoc
//
//	@Summary		List risk threat references
//	@Description	Lists threat references linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id		path		string	true	"Risk ID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[threatIDResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/threat-ids [get]
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

// GetThreatRefForSSP godoc
//
//	@Summary		Get risk threat reference for SSP
//	@Description	Gets a threat reference linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId		path		string	true	"SSP ID"
//	@Param			id			path		string	true	"Risk ID"
//	@Param			threatRefId	path		string	true	"Threat reference ID"
//	@Success		200			{object}	GenericDataResponse[threatIDResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/threat-ids/{threatRefId} [get]
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

// GetThreatRef godoc
//
//	@Summary		Get risk threat reference
//	@Description	Gets a threat reference linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id			path		string	true	"Risk ID"
//	@Param			threatRefId	path		string	true	"Threat reference ID"
//	@Success		200			{object}	GenericDataResponse[threatIDResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/threat-ids/{threatRefId} [get]
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

// AddThreatRefForSSP godoc
//
//	@Summary		Add risk threat reference for SSP
//	@Description	Adds a threat reference to a risk scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId	path		string			true	"SSP ID"
//	@Param			id		path		string			true	"Risk ID"
//	@Param			threat	body		threatIDRequest	true	"Threat reference payload"
//	@Success		201		{object}	GenericDataResponse[threatIDResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/threat-ids [post]
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

// AddThreatRef godoc
//
//	@Summary		Add risk threat reference
//	@Description	Adds a threat reference to a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"Risk ID"
//	@Param			threat	body		threatIDRequest	true	"Threat reference payload"
//	@Success		201		{object}	GenericDataResponse[threatIDResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/threat-ids [post]
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

// UpdateThreatRefForSSP godoc
//
//	@Summary		Update risk threat reference for SSP
//	@Description	Updates a threat reference linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId		path		string			true	"SSP ID"
//	@Param			id			path		string			true	"Risk ID"
//	@Param			threatRefId	path		string			true	"Threat reference ID"
//	@Param			threat		body		threatIDRequest	true	"Threat reference payload"
//	@Success		200			{object}	GenericDataResponse[threatIDResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/threat-ids/{threatRefId} [put]
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

// UpdateThreatRef godoc
//
//	@Summary		Update risk threat reference
//	@Description	Updates a threat reference linked to a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string			true	"Risk ID"
//	@Param			threatRefId	path		string			true	"Threat reference ID"
//	@Param			threat		body		threatIDRequest	true	"Threat reference payload"
//	@Success		200			{object}	GenericDataResponse[threatIDResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/threat-ids/{threatRefId} [put]
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

// DeleteThreatRefForSSP godoc
//
//	@Summary		Delete risk threat reference for SSP
//	@Description	Deletes a threat reference linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId		path	string	true	"SSP ID"
//	@Param			id			path	string	true	"Risk ID"
//	@Param			threatRefId	path	string	true	"Threat reference ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/threat-ids/{threatRefId} [delete]
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

// DeleteThreatRef godoc
//
//	@Summary		Delete risk threat reference
//	@Description	Deletes a threat reference linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id			path	string	true	"Risk ID"
//	@Param			threatRefId	path	string	true	"Threat reference ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/threat-ids/{threatRefId} [delete]
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

// GetRemediationTemplateForSSP godoc
//
//	@Summary		Get risk remediation template for SSP
//	@Description	Gets the remediation template linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path		string	true	"SSP ID"
//	@Param			id		path		string	true	"Risk ID"
//	@Success		200		{object}	GenericDataResponse[remediationTemplateResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/remediation-template [get]
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

// GetRemediationTemplate godoc
//
//	@Summary		Get risk remediation template
//	@Description	Gets the remediation template linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id	path		string	true	"Risk ID"
//	@Success		200	{object}	GenericDataResponse[remediationTemplateResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/remediation-template [get]
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

// CreateRemediationTemplateForSSP godoc
//
//	@Summary		Create risk remediation template for SSP
//	@Description	Creates a remediation template for a risk scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId		path		string						true	"SSP ID"
//	@Param			id			path		string						true	"Risk ID"
//	@Param			template	body		remediationTemplateRequest	true	"Remediation template payload"
//	@Success		201			{object}	GenericDataResponse[remediationTemplateResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/remediation-template [post]
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

// CreateRemediationTemplate godoc
//
//	@Summary		Create risk remediation template
//	@Description	Creates a remediation template for a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Risk ID"
//	@Param			template	body		remediationTemplateRequest	true	"Remediation template payload"
//	@Success		201			{object}	GenericDataResponse[remediationTemplateResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/remediation-template [post]
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

// UpsertRemediationTemplateForSSP godoc
//
//	@Summary		Upsert risk remediation template for SSP
//	@Description	Replaces or creates the remediation template for a risk scoped to an SSP.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			sspId		path		string						true	"SSP ID"
//	@Param			id			path		string						true	"Risk ID"
//	@Param			template	body		remediationTemplateRequest	true	"Remediation template payload"
//	@Success		200			{object}	GenericDataResponse[remediationTemplateResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/remediation-template [put]
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

// UpsertRemediationTemplate godoc
//
//	@Summary		Upsert risk remediation template
//	@Description	Replaces or creates the remediation template for a risk.
//	@Tags			Risks
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Risk ID"
//	@Param			template	body		remediationTemplateRequest	true	"Remediation template payload"
//	@Success		200			{object}	GenericDataResponse[remediationTemplateResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/remediation-template [put]
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

// DeleteRemediationTemplateForSSP godoc
//
//	@Summary		Delete risk remediation template for SSP
//	@Description	Deletes the remediation template linked to a risk scoped to an SSP.
//	@Tags			Risks
//	@Produce		json
//	@Param			sspId	path	string	true	"SSP ID"
//	@Param			id		path	string	true	"Risk ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{sspId}/risks/{id}/remediation-template [delete]
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

// DeleteRemediationTemplate godoc
//
//	@Summary		Delete risk remediation template
//	@Description	Deletes the remediation template linked to a risk.
//	@Tags			Risks
//	@Produce		json
//	@Param			id	path	string	true	"Risk ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/risks/{id}/remediation-template [delete]
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
