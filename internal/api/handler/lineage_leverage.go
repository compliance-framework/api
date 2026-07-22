package handler

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/leverage"
	"github.com/compliance-framework/api/internal/service/relational"
)

// LineageLeverageInheritedFrom names the upstream capability a leverage link consumes,
// with both the offering and the upstream SSP title resolved.
type LineageLeverageInheritedFrom struct {
	UpstreamSSPID    uuid.UUID `json:"upstreamSspId"`
	UpstreamSSPTitle string    `json:"upstreamSspTitle"`
	OfferingID       uuid.UUID `json:"offeringId"`
	OfferingTitle    string    `json:"offeringTitle"`
	OfferingVersion  int       `json:"offeringVersion"`
}

// LineageLeverageLink is one leverage link's full drawer detail. Its JSON is identical
// to oscal's leveragedControlResponse (GET /oscal/system-security-plans/:id/leveraged-controls)
// plus upstreamSspTitle inside inheritedFrom, so the UI reuses one link shape.
type LineageLeverageLink struct {
	ID                          uuid.UUID                          `json:"id"`
	ControlID                   string                             `json:"controlId"`
	StatementID                 *string                            `json:"statementId,omitempty"`
	InheritedFrom               LineageLeverageInheritedFrom       `json:"inheritedFrom"`
	ProvidedUuid                uuid.UUID                          `json:"providedUuid"`
	ByComponentId               *uuid.UUID                         `json:"byComponentId,omitempty"`
	Satisfaction                relational.SSPLeverageSatisfaction `json:"satisfaction"`
	Status                      relational.SSPLeverageStatus       `json:"status"`
	Responsibilities            []leverage.Responsibility          `json:"responsibilities"`
	OutstandingResponsibilities []leverage.Responsibility          `json:"outstandingResponsibilities"`
	// ResponsibilityPosture is keyed by responsibility UUID. UI must fence these keys
	// from camelCasing.
	ResponsibilityPosture map[uuid.UUID]string `json:"responsibilityPosture"`
	DriftRiskID           *uuid.UUID           `json:"driftRiskId,omitempty"`
}

// LineageLeverageRow groups one downstream SSP's leverage links for a control.
type LineageLeverageRow struct {
	SSPID    string                `json:"sspId"`
	SSPTitle string                `json:"sspTitle"`
	Links    []LineageLeverageLink `json:"links"`
}

// LeverageDetail godoc
//
//	@Summary		Per-SSP inherited leverage detail for a control node
//	@Description	Returns, for a control node, one row per downstream System Security Plan that
//	@Description	inherits the control from an upstream offering: every leverage link with its
//	@Description	upstream origin (SSP + offering titles), full and outstanding responsibilities,
//	@Description	live per-responsibility posture, and any open drift risk. Powers the lineage
//	@Description	drawer's inherited-capability panel. Only control keys
//	@Description	(control:<catalogId>/<controlId>) are supported; other node kinds return 400.
//	@Description	Optional sspId filters to a single downstream SSP.
//	@Tags			Lineage
//	@Produce		json
//	@Param			key		path		string	true	"URL-encoded control node key"
//	@Param			sspId	query		string	false	"Filter to a single downstream SSP"
//	@Success		200		{object}	svc.ListResponse[LineageLeverageRow]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/lineage/nodes/{key}/leverage [get]
func (h *LineageHandler) LeverageDetail(ctx echo.Context) error {
	// sspId here is a row filter (which downstream SSP), not a metric scope; componentId
	// is irrelevant to leverage and is ignored.
	var sspFilter *uuid.UUID
	if raw := strings.TrimSpace(ctx.QueryParam("sspId")); raw != "" {
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}
		sspFilter = &id
	}

	kind, catalogID, subID, err := parseNodeKey(ctx.Param("key"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if kind != "control" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("leverage detail is only available for control nodes")))
	}
	ref := relational.ControlRef{CatalogID: catalogID, ControlID: subID}

	// Existence 404: the control must be a real catalog control. A targeted lookup — NOT
	// a full lineage engine build, which would load the entire latest-evidence corpus
	// (loadCompliance -> LoadLatestEvidenceStreams) on every drawer open just for two
	// fields. Rejected alternative: having the UI call per-SSP
	// /oscal/system-security-plans/:id/leveraged-controls would be N requests and would
	// require ssp:read on each SSP — the read guard here is the same as /ssps.
	if err := h.db.Select("id").
		Where("catalog_id = ? AND id = ?", ref.CatalogID, ref.ControlID).
		First(&relational.Control{}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("control not found")))
		}
		h.sugar.Errorw("failed to look up control", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Leverage matches by control-id only (no catalog id), the established precedent.
	projectionsBySSP, err := leverage.ProjectForControl(h.db, subID)
	if err != nil {
		h.sugar.Errorw("failed to project leverage for control", "controlID", subID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Downstream + upstream SSP titles in one Preload query, keyed on the ids
	// ProjectForControl already surfaces (mirrors collectInheritedSharedResponsibility).
	sspTitleByID, err := h.leverageSSPTitles(projectionsBySSP, sspFilter)
	if err != nil {
		h.sugar.Errorw("failed to resolve SSP titles", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	rows := make([]LineageLeverageRow, 0, len(projectionsBySSP))
	for sspID, projections := range projectionsBySSP {
		if sspFilter != nil && sspID != *sspFilter {
			continue
		}
		links := make([]LineageLeverageLink, 0, len(projections))
		for _, p := range projections {
			var byComponentID *uuid.UUID
			if p.ByComponentID != uuid.Nil {
				id := p.ByComponentID
				byComponentID = &id
			}
			links = append(links, LineageLeverageLink{
				ID:          *p.Link.ID,
				ControlID:   p.Link.ControlID,
				StatementID: p.Link.StatementID,
				InheritedFrom: LineageLeverageInheritedFrom{
					UpstreamSSPID:    p.Link.UpstreamSSPID,
					UpstreamSSPTitle: sspTitleByID[p.Link.UpstreamSSPID],
					OfferingID:       p.Link.OfferingID,
					OfferingTitle:    p.OfferingTitle,
					OfferingVersion:  p.Link.OfferingVersion,
				},
				ProvidedUuid:                p.Link.ProvidedUUID,
				ByComponentId:               byComponentID,
				Satisfaction:                p.Satisfaction,
				Status:                      p.Link.Status,
				Responsibilities:            p.Responsibilities,
				OutstandingResponsibilities: p.Outstanding,
				ResponsibilityPosture:       p.Posture,
				DriftRiskID:                 p.DriftRiskID,
			})
		}
		rows = append(rows, LineageLeverageRow{
			SSPID:    sspID.String(),
			SSPTitle: sspTitleByID[sspID],
			Links:    links,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SSPTitle == rows[j].SSPTitle {
			return rows[i].SSPID < rows[j].SSPID
		}
		return rows[i].SSPTitle < rows[j].SSPTitle
	})

	limit := len(rows)
	if limit < 1 {
		limit = 1
	}
	return ctx.JSON(http.StatusOK, svc.NewListResponse(rows, int64(len(rows)), 1, limit))
}

// leverageSSPTitles resolves the Metadata.Title of every SSP the drawer names — the
// downstream SSPs (the projection keys) and their upstream SSPs (each link's
// UpstreamSSPID) — in a single Preload query, optionally narrowed to one downstream
// SSP. Mirrors collectInheritedSharedResponsibility's title resolution.
func (h *LineageHandler) leverageSSPTitles(projectionsBySSP map[uuid.UUID][]leverage.Projection, sspFilter *uuid.UUID) (map[uuid.UUID]string, error) {
	seen := map[uuid.UUID]struct{}{}
	ids := make([]uuid.UUID, 0)
	add := func(id uuid.UUID) {
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for sspID, projections := range projectionsBySSP {
		if sspFilter != nil && sspID != *sspFilter {
			continue
		}
		add(sspID) // downstream
		for _, p := range projections {
			add(p.Link.UpstreamSSPID) // upstream
		}
	}

	titles := make(map[uuid.UUID]string, len(ids))
	if len(ids) == 0 {
		return titles, nil
	}
	var ssps []relational.SystemSecurityPlan
	if err := h.db.Preload("Metadata").Where("id IN ?", ids).Find(&ssps).Error; err != nil {
		return nil, err
	}
	for i := range ssps {
		if ssps[i].ID == nil {
			continue
		}
		titles[*ssps[i].ID] = ssps[i].Metadata.Title
	}
	return titles, nil
}
