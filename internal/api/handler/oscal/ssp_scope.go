package oscal

import (
	"errors"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/sspscope"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// SSPScopeHandler serves an SSP's scope: the labels that identify its evidence.
type SSPScopeHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
	scope *sspscope.Service
}

func NewSSPScopeHandler(sugar *zap.SugaredLogger, db *gorm.DB) *SSPScopeHandler {
	return &SSPScopeHandler{sugar: sugar, db: db, scope: sspscope.NewService(db)}
}

// Register mounts the scope routes on the SSP group. There is deliberately no DELETE for
// entries: an entry is removed by adding an exception for it.
func (h *SSPScopeHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("/:id/scope", h.Get, guard.Read())
	api.PUT("/:id/scope", h.Update, guard.Update())
	api.POST("/:id/scope/entries", h.AddEntry, guard.Update())
	api.POST("/:id/scope/exceptions", h.AddException, guard.Update())
	api.DELETE("/:id/scope/exceptions/:exceptionId", h.DeleteException, guard.Update())
}

type sspScopeLabelsRequest struct {
	Labels []relational.ScopeLabel `json:"labels" validate:"required"`
}

type sspScopeUpdateRequest struct {
	AutoFilters *bool `json:"auto-filters" validate:"required"`
}

type sspScopeEntryResponse struct {
	ID         uuid.UUID               `json:"id"`
	Labels     []relational.ScopeLabel `json:"labels"`
	Origin     string                  `json:"origin"`
	TemplateID *uuid.UUID              `json:"template-id"`
	CreatedAt  time.Time               `json:"created-at"`
}

type sspScopeExceptionResponse struct {
	ID        uuid.UUID               `json:"id"`
	Labels    []relational.ScopeLabel `json:"labels"`
	CreatedAt time.Time               `json:"created-at"`
}

type sspScopeResponse struct {
	AutoFilters bool                        `json:"auto-filters"`
	Entries     []sspScopeEntryResponse     `json:"entries"`
	Exceptions  []sspScopeExceptionResponse `json:"exceptions"`
}

func newSSPScopeEntryResponse(entry relational.SSPScopeEntry) sspScopeEntryResponse {
	return sspScopeEntryResponse{
		ID:         *entry.ID,
		Labels:     entry.Labels,
		Origin:     entry.Origin,
		TemplateID: entry.TemplateID,
		CreatedAt:  entry.CreatedAt,
	}
}

func newSSPScopeExceptionResponse(exception relational.SSPScopeException) sspScopeExceptionResponse {
	return sspScopeExceptionResponse{
		ID:        *exception.ID,
		Labels:    exception.Labels,
		CreatedAt: exception.CreatedAt,
	}
}

// Get godoc
//
//	@Summary		Get an SSP's scope
//	@Description	Returns the scope entries (evidence matching any entry is in scope), the exceptions and the automatic-filter setting of a System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataResponse[sspScopeResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/scope [get]
func (h *SSPScopeHandler) Get(ctx *echo.Context) error {
	sspID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return h.respondScope(ctx, sspID)
}

// Update godoc
//
//	@Summary		Update an SSP's scope settings
//	@Description	Turns automatic per-policy filters on or off for the System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"SSP ID"
//	@Param			request	body		sspScopeUpdateRequest	true	"Scope settings"
//	@Success		200		{object}	handler.GenericDataResponse[sspScopeResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/scope [put]
func (h *SSPScopeHandler) Update(ctx *echo.Context) error {
	sspID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var req sspScopeUpdateRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if req.AutoFilters == nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("auto-filters is required")))
	}
	if err := h.scope.SetAutoFilters(sspID, *req.AutoFilters); err != nil {
		return h.scopeError(ctx, err)
	}
	return h.respondScope(ctx, sspID)
}

// AddEntry godoc
//
//	@Summary		Add an SSP scope entry
//	@Description	Adds an entry to the SSP's scope: evidence carrying all of its labels is in scope. Removes an exception with the same labels.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"SSP ID"
//	@Param			request	body		sspScopeLabelsRequest	true	"Entry labels"
//	@Success		201		{object}	handler.GenericDataResponse[sspScopeEntryResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/scope/entries [post]
func (h *SSPScopeHandler) AddEntry(ctx *echo.Context) error {
	sspID, labels, actor, ok := h.bindLabels(ctx)
	if !ok {
		return nil
	}
	entry, err := h.scope.AddEntry(sspID, labels, actor)
	if err != nil {
		return h.scopeError(ctx, err)
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[sspScopeEntryResponse]{Data: newSSPScopeEntryResponse(entry)})
}

// AddException godoc
//
//	@Summary		Add an SSP scope exception
//	@Description	Removes the entry with the same labels from the SSP's scope, and stops SSP templates from learning it again. Refused with 409 when it would remove the last entry while filters follow the scope.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"SSP ID"
//	@Param			request	body		sspScopeLabelsRequest	true	"Exception labels"
//	@Success		201		{object}	handler.GenericDataResponse[sspScopeExceptionResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/scope/exceptions [post]
func (h *SSPScopeHandler) AddException(ctx *echo.Context) error {
	sspID, labels, actor, ok := h.bindLabels(ctx)
	if !ok {
		return nil
	}
	exception, err := h.scope.AddException(sspID, labels, actor)
	if err != nil {
		return h.scopeError(ctx, err)
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[sspScopeExceptionResponse]{Data: newSSPScopeExceptionResponse(exception)})
}

// DeleteException godoc
//
//	@Summary		Delete an SSP scope exception
//	@Description	Deletes only the exception: the entry does not come back. A template run re-learns it if evidence still shows it, or the user adds it again.
//	@Tags			System Security Plans
//	@Param			id			path	string	true	"SSP ID"
//	@Param			exceptionId	path	string	true	"Exception ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/scope/exceptions/{exceptionId} [delete]
func (h *SSPScopeHandler) DeleteException(ctx *echo.Context) error {
	sspID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	exceptionID, err := uuid.Parse(ctx.Param("exceptionId"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := h.scope.DeleteException(sspID, exceptionID); err != nil {
		return h.scopeError(ctx, err)
	}
	return ctx.NoContent(http.StatusNoContent)
}

func (h *SSPScopeHandler) respondScope(ctx *echo.Context, sspID uuid.UUID) error {
	scope, err := h.scope.Get(sspID)
	if err != nil {
		return h.scopeError(ctx, err)
	}
	out := sspScopeResponse{
		AutoFilters: scope.AutoFilters,
		Entries:     make([]sspScopeEntryResponse, 0, len(scope.Entries)),
		Exceptions:  make([]sspScopeExceptionResponse, 0, len(scope.Exceptions)),
	}
	for _, entry := range scope.Entries {
		out.Entries = append(out.Entries, newSSPScopeEntryResponse(entry))
	}
	for _, exception := range scope.Exceptions {
		out.Exceptions = append(out.Exceptions, newSSPScopeExceptionResponse(exception))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[sspScopeResponse]{Data: out})
}

// bindLabels parses the SSP id, the labels body and the acting user. On failure it has
// already written the response and returns ok=false.
func (h *SSPScopeHandler) bindLabels(ctx *echo.Context) (uuid.UUID, []relational.ScopeLabel, *uuid.UUID, bool) {
	sspID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return uuid.Nil, nil, nil, false
	}
	var req sspScopeLabelsRequest
	if err := ctx.Bind(&req); err != nil {
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return uuid.Nil, nil, nil, false
	}
	actor, err := h.actor(ctx)
	if err != nil {
		h.sugar.Errorw("Failed to resolve scope actor", "ssp", sspID, "error", err)
		_ = ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		return uuid.Nil, nil, nil, false
	}
	return sspID, req.Labels, actor, true
}

// actor returns the id of the calling user, or nil when the caller is not a known user.
func (h *SSPScopeHandler) actor(ctx *echo.Context) (*uuid.UUID, error) {
	claims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || claims == nil {
		return nil, nil
	}
	var users []relational.User
	if err := h.db.Where("email = ?", claims.Subject).Limit(1).Find(&users).Error; err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0].ID, nil
}

func (h *SSPScopeHandler) scopeError(ctx *echo.Context, err error) error {
	switch {
	case errors.Is(err, sspscope.ErrSSPNotFound), errors.Is(err, sspscope.ErrExceptionNotFound):
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	case errors.Is(err, sspscope.ErrInvalidLabels), errors.Is(err, sspscope.ErrLimitExceeded):
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	case errors.Is(err, sspscope.ErrDuplicateEntry), errors.Is(err, sspscope.ErrDuplicateException), errors.Is(err, sspscope.ErrScopeWouldEmpty):
		return ctx.JSON(http.StatusConflict, api.NewError(err))
	}
	h.sugar.Errorw("SSP scope operation failed", "ssp", ctx.Param("id"), "error", err)
	return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
}
