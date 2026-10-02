package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational/subjects"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// maxSubjectLookupIDs caps the ids lookup to one page at the largest page size.
const maxSubjectLookupIDs = 100

type SubjectHandler struct {
	service    *subjects.Service
	pagination *svc.PaginationConfig
	sugar      *zap.SugaredLogger
}

func NewSubjectHandler(sugar *zap.SugaredLogger, db *gorm.DB) *SubjectHandler {
	return &SubjectHandler{
		service:    subjects.NewService(db),
		pagination: svc.NewPaginationConfig(),
		sugar:      sugar,
	}
}

func (h *SubjectHandler) Register(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.GET("", h.List, middlewares...)
}

// List godoc
//
//	@Summary		List subjects
//	@Description	Lists the entities evidence can name as its subject: defined components, SSP system components, parties and users. Used to pick and filter evidence subjects.
//	@Tags			Subjects
//	@Produce		json
//	@Param			search	query		string	false	"Case-insensitive title search"
//	@Param			kind	query		string	false	"Comma-separated kinds: defined-component, system-component, party, user"
//	@Param			ssp		query		string	false	"Only system components of this SSP"
//	@Param			ids		query		string	false	"Comma-separated subject UUIDs to look up (at most 100)"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[subjects.Summary]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/subjects [get]
func (h *SubjectHandler) List(ctx echo.Context) error {
	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	params := subjects.ListParams{
		Search: ctx.QueryParam("search"),
		Limit:  pagination.Limit,
		Offset: pagination.Offset,
	}
	if raw := strings.TrimSpace(ctx.QueryParam("kind")); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			kind, ok := subjects.ParseKind(value)
			if !ok {
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("unsupported kind %q", strings.TrimSpace(value))))
			}
			params.Kinds = append(params.Kinds, kind)
		}
	}
	if raw := strings.TrimSpace(ctx.QueryParam("ids")); raw != "" {
		values := strings.Split(raw, ",")
		if len(values) > maxSubjectLookupIDs {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("ids accepts at most %d subjects", maxSubjectLookupIDs)))
		}
		for _, value := range values {
			id, err := uuid.Parse(strings.TrimSpace(value))
			if err != nil {
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid ids: %w", err)))
			}
			params.IDs = append(params.IDs, id)
		}
	}
	if raw := strings.TrimSpace(ctx.QueryParam("ssp")); raw != "" {
		sspID, err := uuid.Parse(raw)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid ssp: %w", err)))
		}
		params.SSPID = &sspID
	}

	items, total, err := h.service.List(params)
	if err != nil {
		h.sugar.Errorw("Failed to list subjects", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, svc.NewListResponse(items, total, pagination.Page, pagination.Limit))
}
