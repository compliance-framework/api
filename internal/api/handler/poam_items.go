package handler

import (
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type PoamItemsHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func NewPoamItemsHandler(logger *zap.SugaredLogger, db *gorm.DB) *PoamItemsHandler {
	return &PoamItemsHandler{db: db, sugar: logger}
}

func (h *PoamItemsHandler) Register(g *echo.Group) {
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.Get)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
	g.GET("/:id/milestones", h.ListMilestones)
	g.POST("/:id/milestones", h.AddMilestone)
	g.PUT("/:id/milestones/:milestoneId", h.UpdateMilestone)
	g.DELETE("/:id/milestones/:milestoneId", h.DeleteMilestone)
}

type createMilestone struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	DueDate     *time.Time `json:"dueDate"`
}

type createPoam struct {
	SspID            string            `json:"sspId"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Status           string            `json:"status"`
	Deadline         *time.Time        `json:"deadline"`
	ResourceRequired *string           `json:"resourceRequired"`
	PocName          *string           `json:"pocName"`
	PocEmail         *string           `json:"pocEmail"`
	PocPhone         *string           `json:"pocPhone"`
	Remarks          *string           `json:"remarks"`
	RiskIDs          []string          `json:"riskIds"`
	Milestones       []createMilestone `json:"milestones"`
}

type PoamItemWithLinksResponse struct {
	Item      relational.CcfPoamItem           `json:"item"`
	RiskLinks []relational.CcfPoamItemRiskLink `json:"riskLinks"`
}

// Create godoc
//
//	@Summary		Create a POAM item
//	@Description	Creates a POAM item with optional milestones and risk links in a single transaction.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			body	body		createPoam	true	"POAM item payload"
//	@Success		201		{object}	GenericDataResponse[relational.CcfPoamItem]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/poam-items [post]
func (h *PoamItemsHandler) Create(c echo.Context) error {
	var in createPoam
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	ssp, err := uuid.Parse(in.SspID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	item := relational.CcfPoamItem{
		ID:               uuid.New(),
		SspID:            ssp,
		Title:            in.Title,
		Description:      in.Description,
		Status:           in.Status,
		Deadline:         in.Deadline,
		ResourceRequired: in.ResourceRequired,
		PocName:          in.PocName,
		PocEmail:         in.PocEmail,
		PocPhone:         in.PocPhone,
		Remarks:          in.Remarks,
	}
	err = h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&item).Error; err != nil {
			return err
		}
		for _, m := range in.Milestones {
			ms := relational.CcfPoamItemMilestone{
				ID:          uuid.New(),
				PoamItemID:  item.ID,
				Title:       m.Title,
				Description: m.Description,
				Status:      m.Status,
				DueDate:     m.DueDate,
			}
			if err := tx.Create(&ms).Error; err != nil {
				return err
			}
		}
		for _, rid := range in.RiskIDs {
			ruuid, err := uuid.Parse(rid)
			if err != nil {
				return err
			}
			link := relational.CcfPoamItemRiskLink{PoamItemID: item.ID, RiskID: ruuid}
			if err := tx.Create(&link).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[relational.CcfPoamItem]{Data: item})
}

// List godoc
//
//	@Summary		List POAM items
//	@Description	List POAM items filtered by status, sspId, riskId, or deadlineBefore.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			status			query		string	false	"open|in-progress|completed|overdue"
//	@Param			sspId			query		string	false	"SSP UUID"
//	@Param			riskId			query		string	false	"Risk UUID"
//	@Param			deadlineBefore	query		string	false	"RFC3339 timestamp"
//	@Success		200				{object}	GenericDataListResponse[relational.CcfPoamItem]
//	@Failure		500				{object}	api.Error
//	@Router			/poam-items [get]
func (h *PoamItemsHandler) List(c echo.Context) error {
	var items []relational.CcfPoamItem
	q := h.db.Model(&relational.CcfPoamItem{})
	if v := c.QueryParam("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := c.QueryParam("sspId"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			q = q.Where("ssp_id = ?", id)
		}
	}
	if v := c.QueryParam("deadlineBefore"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q = q.Where("deadline IS NOT NULL AND deadline < ?", t)
		}
	}
	if v := c.QueryParam("riskId"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			q = q.Joins("JOIN poam_item_risk_links l ON l.poam_item_id = ccf_poam_items.id AND l.risk_id = ?", id)
		}
	}
	if err := q.Find(&items).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItem]{Data: items})
}

// Get godoc
//
//	@Summary		Get POAM item
//	@Description	Get a POAM item with its milestones and risk links.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataResponse[PoamItemWithLinksResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/poam-items/{id} [get]
func (h *PoamItemsHandler) Get(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var item relational.CcfPoamItem
	if err := h.db.Preload("Milestones").First(&item, "id = ?", id).Error; err != nil {
		return c.JSON(http.StatusNotFound, api.NewError(err))
	}
	var links []relational.CcfPoamItemRiskLink
	_ = h.db.Where("poam_item_id = ?", id).Find(&links).Error
	return c.JSON(http.StatusOK, GenericDataResponse[PoamItemWithLinksResponse]{Data: PoamItemWithLinksResponse{Item: item, RiskLinks: links}})
}

// Update godoc
//
//	@Summary		Update POAM item
//	@Description	Updates mutable fields of a POAM item.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"POAM item ID"
//	@Param			body	body		map[string]interface{}	true	"Fields to update"
//	@Success		200		{object}	GenericDataResponse[relational.CcfPoamItem]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/poam-items/{id} [put]
func (h *PoamItemsHandler) Update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var in map[string]interface{}
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	delete(in, "id")
	delete(in, "milestones")
	delete(in, "riskIds")
	if err := h.db.Model(&relational.CcfPoamItem{}).Where("id = ?", id).Updates(in).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	var out relational.CcfPoamItem
	_ = h.db.First(&out, "id = ?", id).Error
	return c.JSON(http.StatusOK, GenericDataResponse[relational.CcfPoamItem]{Data: out})
}

// Delete godoc
//
//	@Summary		Delete POAM item
//	@Description	Deletes a POAM item and cascades to milestones and risk links.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		204	{string}	string	"no content"
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/poam-items/{id} [delete]
func (h *PoamItemsHandler) Delete(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	err = h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("poam_item_id = ?", id).Delete(&relational.CcfPoamItemRiskLink{}).Error; err != nil {
			return err
		}
		if err := tx.Where("poam_item_id = ?", id).Delete(&relational.CcfPoamItemMilestone{}).Error; err != nil {
			return err
		}
		return tx.Delete(&relational.CcfPoamItem{}, "id = ?", id).Error
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.NoContent(http.StatusNoContent)
}

// ListMilestones godoc
//
//	@Summary		List milestones
//	@Description	List all milestones for a POAM item.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id	path		string	true	"POAM item ID"
//	@Success		200	{object}	GenericDataListResponse[relational.CcfPoamItemMilestone]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/poam-items/{id}/milestones [get]
func (h *PoamItemsHandler) ListMilestones(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ms []relational.CcfPoamItemMilestone
	if err := h.db.Where("poam_item_id = ?", id).Find(&ms).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusOK, GenericDataListResponse[relational.CcfPoamItemMilestone]{Data: ms})
}

// AddMilestone godoc
//
//	@Summary		Add milestone
//	@Description	Add a milestone to a POAM item.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"POAM item ID"
//	@Param			body	body		createMilestone	true	"Milestone payload"
//	@Success		201		{object}	GenericDataResponse[relational.CcfPoamItemMilestone]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/poam-items/{id}/milestones [post]
func (h *PoamItemsHandler) AddMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var in createMilestone
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	m := relational.CcfPoamItemMilestone{
		ID:          uuid.New(),
		PoamItemID:  id,
		Title:       in.Title,
		Description: in.Description,
		Status:      in.Status,
		DueDate:     in.DueDate,
	}
	if err := h.db.Create(&m).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.JSON(http.StatusCreated, GenericDataResponse[relational.CcfPoamItemMilestone]{Data: m})
}

// UpdateMilestone godoc
//
//	@Summary		Update milestone
//	@Description	Update milestone fields; when status becomes completed, sets completed_at.
//	@Tags			POAM Items
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"POAM item ID"
//	@Param			milestoneId	path		string					true	"Milestone ID"
//	@Param			body		body		map[string]interface{}	true	"Fields to update"
//	@Success		200			{object}	GenericDataResponse[relational.CcfPoamItemMilestone]
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/poam-items/{id}/milestones/{milestoneId} [put]
func (h *PoamItemsHandler) UpdateMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	mid, err := uuid.Parse(c.Param("milestoneId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var in map[string]interface{}
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if v, ok := in["status"]; ok && v == "completed" {
		now := time.Now().UTC()
		in["completed_at"] = &now
	}
	if err := h.db.Model(&relational.CcfPoamItemMilestone{}).Where("poam_item_id = ? AND id = ?", id, mid).Updates(in).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	var out relational.CcfPoamItemMilestone
	_ = h.db.First(&out, "id = ?", mid).Error
	return c.JSON(http.StatusOK, GenericDataResponse[relational.CcfPoamItemMilestone]{Data: out})
}

// DeleteMilestone godoc
//
//	@Summary		Delete milestone
//	@Description	Delete a milestone from a POAM item.
//	@Tags			POAM Items
//	@Produce		json
//	@Param			id			path		string	true	"POAM item ID"
//	@Param			milestoneId	path		string	true	"Milestone ID"
//	@Success		204			{string}	string	"no content"
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/poam-items/{id}/milestones/{milestoneId} [delete]
func (h *PoamItemsHandler) DeleteMilestone(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	mid, err := uuid.Parse(c.Param("milestoneId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.db.Where("poam_item_id = ? AND id = ?", id, mid).Delete(&relational.CcfPoamItemMilestone{}).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return c.NoContent(http.StatusNoContent)
}
