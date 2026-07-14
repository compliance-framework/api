package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// SharedResponsibilityProvides is one statement-anchored by-component this SSP exports from:
// what it provides, and what it makes a consumer responsible for.
type SharedResponsibilityProvides struct {
	ControlID   string `json:"controlId"`
	StatementID string `json:"statementId"`

	ByComponentUUID uuid.UUID `json:"byComponentUuid"`
	ComponentUUID   uuid.UUID `json:"componentUuid"`
	ComponentTitle  string    `json:"componentTitle"`

	ExportUUID uuid.UUID `json:"exportUuid"`

	Provided         []controlExportProvided       `json:"provided"`
	Responsibilities []controlExportResponsibility `json:"responsibilities"`

	// Offered reports whether an item on one of this SSP's *published* offerings already points
	// at one of these provided-uuids — i.e. whether a downstream can actually find and subscribe
	// to the capability, as opposed to it merely existing in the control-implementation tree.
	// An item on a draft/deprecated/revoked offering does not count: nothing can reach it.
	Offered bool `json:"offered"`
}

// SharedResponsibilityInherits is one upstream capability this SSP consumes, projected from
// the leverage link rather than re-derived — so satisfaction here always agrees with what
// GET /leveraged-controls reports.
type SharedResponsibilityInherits struct {
	ControlID   string  `json:"controlId"`
	StatementID *string `json:"statementId,omitempty"`

	ByComponentUUID uuid.UUID `json:"byComponentUuid"`
	InheritedUUID   uuid.UUID `json:"inheritedUuid"`
	ProvidedUUID    uuid.UUID `json:"providedUuid"`

	UpstreamSSPID    uuid.UUID `json:"upstreamSspId"`
	UpstreamSSPTitle string    `json:"upstreamSspTitle"`

	OfferingID      uuid.UUID `json:"offeringId"`
	OfferingVersion int       `json:"offeringVersion"`

	LeverageLinkID uuid.UUID                          `json:"leverageLinkId"`
	Satisfaction   relational.SSPLeverageSatisfaction `json:"satisfaction"`
	Status         relational.SSPLeverageStatus       `json:"status"`

	Description string `json:"description"`
}

// SharedResponsibilitySatisfies is one upstream responsibility this SSP has discharged.
type SharedResponsibilitySatisfies struct {
	ControlID   string `json:"controlId"`
	StatementID string `json:"statementId"`

	ByComponentUUID    uuid.UUID `json:"byComponentUuid"`
	SatisfiedUUID      uuid.UUID `json:"satisfiedUuid"`
	ResponsibilityUUID uuid.UUID `json:"responsibilityUuid"`

	Description      string                             `json:"description"`
	ResponsibleRoles []oscalTypes_1_1_3.ResponsibleRole `json:"responsibleRoles"`
}

// SharedResponsibilityLegacy is one requirement-anchored by-component still carrying shared
// responsibility. These can't be expressed in the statement-anchored model, so they're
// surfaced explicitly rather than silently dropped: they are exactly the rows the
// requirement-level DELETE exists to wind down.
type SharedResponsibilityLegacy struct {
	ControlID       string    `json:"controlId"`
	ByComponentUUID uuid.UUID `json:"byComponentUuid"`
	Reason          string    `json:"reason"`
}

// SharedResponsibilityRollup is everything one SSP provides, inherits and satisfies —
// flattened and statement-keyed, so neither the Controls page nor the Export Offerings tab
// has to walk the control-implementation tree to render it.
type SharedResponsibilityRollup struct {
	Provides  []SharedResponsibilityProvides  `json:"provides"`
	Inherits  []SharedResponsibilityInherits  `json:"inherits"`
	Satisfies []SharedResponsibilitySatisfies `json:"satisfies"`
	Legacy    []SharedResponsibilityLegacy    `json:"legacy"`
}

// SharedResponsibility godoc
//
//	@Summary		Roll up everything one SSP provides, inherits and satisfies
//	@Description	A flat, statement-keyed projection of this SSP's shared-responsibility posture:
//	@Description	what it exports (with the provided capabilities and the responsibilities it
//	@Description	pushes onto consumers, and whether each is offered on a *published* offering —
//	@Description	a draft/deprecated/revoked one does not count, since no downstream can reach
//	@Description	it), what it inherits
//	@Description	from upstreams (with live-recomputed satisfaction and link status), how it
//	@Description	discharges upstream responsibilities, and any legacy requirement-anchored
//	@Description	by-components still to be migrated.
//	@Description
//	@Description	The inherits arm reuses the same batched projection GET /leveraged-controls
//	@Description	serves, so the two can never disagree about satisfaction. Optionally filter the
//	@Description	whole rollup to one control with controlId.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id			path		string	true	"SSP ID"
//	@Param			controlId	query		string	false	"Only include rows for this control"
//	@Success		200			{object}	handler.GenericDataResponse[SharedResponsibilityRollup]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/shared-responsibility [get]
func (h *SystemSecurityPlanHandler) SharedResponsibility(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	controlFilter := strings.TrimSpace(ctx.QueryParam("controlId"))

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorf("Failed to load SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	rollup := SharedResponsibilityRollup{
		Provides:  []SharedResponsibilityProvides{},
		Inherits:  []SharedResponsibilityInherits{},
		Satisfies: []SharedResponsibilitySatisfies{},
		Legacy:    []SharedResponsibilityLegacy{},
	}

	if ssp.ControlImplementation.ID != nil {
		if err := h.collectOwnedSharedResponsibility(&rollup, sspID, *ssp.ControlImplementation.ID, controlFilter); err != nil {
			h.sugar.Errorf("Failed to roll up owned shared responsibility: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	if err := h.collectInheritedSharedResponsibility(&rollup, sspID, controlFilter); err != nil {
		h.sugar.Errorf("Failed to roll up inherited shared responsibility: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[SharedResponsibilityRollup]{Data: rollup})
}

// collectOwnedSharedResponsibility fills the provides / satisfies / legacy arms from the SSP's
// own control-implementation tree, in a fixed number of queries regardless of tree size: the
// requirements, their statements, every by-component under either, and then the exports,
// satisfied rows, components and offering items in one batch each.
func (h *SystemSecurityPlanHandler) collectOwnedSharedResponsibility(rollup *SharedResponsibilityRollup, sspID, controlImplementationID uuid.UUID, controlFilter string) error {
	requirementQuery := h.db.Where("control_implementation_id = ?", controlImplementationID)
	if controlFilter != "" {
		requirementQuery = requirementQuery.Where("UPPER(control_id) = UPPER(?)", controlFilter)
	}
	var requirements []relational.ImplementedRequirement
	if err := requirementQuery.Order("id ASC").Find(&requirements).Error; err != nil {
		return err
	}
	if len(requirements) == 0 {
		return nil
	}
	requirementIDs := make([]uuid.UUID, 0, len(requirements))
	controlIDByRequirement := make(map[uuid.UUID]string, len(requirements))
	for _, r := range requirements {
		requirementIDs = append(requirementIDs, *r.ID)
		controlIDByRequirement[*r.ID] = r.ControlId
	}

	var statements []relational.Statement
	if err := h.db.Where("implemented_requirement_id IN ?", requirementIDs).Order("id ASC").Find(&statements).Error; err != nil {
		return err
	}
	statementIDs := make([]uuid.UUID, 0, len(statements))
	statementByID := make(map[uuid.UUID]relational.Statement, len(statements))
	for _, s := range statements {
		statementIDs = append(statementIDs, *s.ID)
		statementByID[*s.ID] = s
	}

	// One query for both anchoring levels: requirement-anchored rows are legacy but must
	// still be reported, so they can't simply be filtered out of the read.
	byComponentQuery := h.db.Where("parent_id IN ? AND parent_type = ?", requirementIDs, "implemented_requirements")
	if len(statementIDs) > 0 {
		byComponentQuery = byComponentQuery.Or("parent_id IN ? AND parent_type = ?", statementIDs, "statements")
	}
	var byComponents []relational.ByComponent
	if err := byComponentQuery.Order("id ASC").Find(&byComponents).Error; err != nil {
		return err
	}
	if len(byComponents) == 0 {
		return nil
	}

	byComponentIDs := make([]uuid.UUID, 0, len(byComponents))
	for _, bc := range byComponents {
		byComponentIDs = append(byComponentIDs, *bc.ID)
	}

	var exports []relational.Export
	if err := h.db.
		Preload("Provided").
		Preload("Responsibilities").
		Where("by_component_id IN ?", byComponentIDs).
		Find(&exports).Error; err != nil {
		return err
	}
	exportByComponent := make(map[uuid.UUID]relational.Export, len(exports))
	for _, e := range exports {
		exportByComponent[e.ByComponentId] = e
	}

	var satisfiedRows []relational.SatisfiedControlImplementationResponsibility
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Where("by_component_id IN ?", byComponentIDs).
		Order("id ASC").
		Find(&satisfiedRows).Error; err != nil {
		return err
	}

	componentUUIDs := uniqueUUIDs(byComponents, func(bc relational.ByComponent) uuid.UUID { return bc.ComponentUUID })
	var components []relational.SystemComponent
	if err := h.db.Where("id IN ?", componentUUIDs).Find(&components).Error; err != nil {
		return err
	}
	componentTitleByID := make(map[uuid.UUID]string, len(components))
	for _, c := range components {
		componentTitleByID[*c.ID] = c.Title
	}

	// Which of this SSP's provided-uuids are actually published in one of its own offerings.
	// Published-only, deliberately: a draft/deprecated/revoked offering is invisible to every
	// downstream (ListAll and ByControl are published-only, and Subscribe 404s on anything else),
	// so counting one as "offered" would claim a capability is available to leverage when nothing
	// can reach it. A curator sees their own drafts via GET /:id/export-offerings.
	var offeredItems []relational.SSPExportOfferingItem
	if err := h.db.
		Joins("JOIN ssp_export_offerings ON ssp_export_offerings.id = ssp_export_offering_items.offering_id").
		Where("ssp_export_offerings.ssp_id = ? AND ssp_export_offerings.status = ?",
			sspID, relational.SSPExportOfferingStatusPublished).
		Find(&offeredItems).Error; err != nil {
		return err
	}
	offeredProvidedUUIDs := make(map[uuid.UUID]bool, len(offeredItems))
	for _, item := range offeredItems {
		offeredProvidedUUIDs[item.ProvidedUUID] = true
	}

	// Resolve each by-component's (controlId, statementId) once, and split legacy off.
	type anchor struct {
		controlID   string
		statementID string
		legacy      bool
	}
	anchorByComponent := make(map[uuid.UUID]anchor, len(byComponents))
	for _, bc := range byComponents {
		if bc.ParentID == nil || bc.ParentType == nil {
			continue
		}
		switch *bc.ParentType {
		case "statements":
			stmt, ok := statementByID[*bc.ParentID]
			if !ok {
				continue
			}
			anchorByComponent[*bc.ID] = anchor{
				controlID:   controlIDByRequirement[stmt.ImplementedRequirementId],
				statementID: stmt.StatementId,
			}
		case "implemented_requirements":
			anchorByComponent[*bc.ID] = anchor{
				controlID: controlIDByRequirement[*bc.ParentID],
				legacy:    true,
			}
		}
	}

	for _, bc := range byComponents {
		a, ok := anchorByComponent[*bc.ID]
		if !ok {
			continue
		}

		if a.legacy {
			rollup.Legacy = append(rollup.Legacy, SharedResponsibilityLegacy{
				ControlID:       a.controlID,
				ByComponentUUID: *bc.ID,
				Reason:          "requirement-anchored export",
			})
			continue
		}

		export, hasExport := exportByComponent[*bc.ID]
		if !hasExport {
			continue
		}

		provided := make([]controlExportProvided, 0, len(export.Provided))
		offered := false
		for _, p := range export.Provided {
			provided = append(provided, controlExportProvided{UUID: *p.ID, Description: p.Description})
			if offeredProvidedUUIDs[*p.ID] {
				offered = true
			}
		}

		responsibilities := make([]controlExportResponsibility, 0, len(export.Responsibilities))
		for _, r := range export.Responsibilities {
			responsibilities = append(responsibilities, controlExportResponsibility{
				UUID:         *r.ID,
				Description:  r.Description,
				ProvidedUUID: r.ProvidedUuid,
			})
		}

		rollup.Provides = append(rollup.Provides, SharedResponsibilityProvides{
			ControlID:        a.controlID,
			StatementID:      a.statementID,
			ByComponentUUID:  *bc.ID,
			ComponentUUID:    bc.ComponentUUID,
			ComponentTitle:   componentTitleByID[bc.ComponentUUID],
			ExportUUID:       *export.ID,
			Provided:         provided,
			Responsibilities: responsibilities,
			Offered:          offered,
		})
	}

	for i := range satisfiedRows {
		s := satisfiedRows[i]
		a, ok := anchorByComponent[s.ByComponentId]
		if !ok || a.legacy {
			continue
		}

		roles := make([]oscalTypes_1_1_3.ResponsibleRole, 0, len(s.ResponsibleRoles))
		for j := range s.ResponsibleRoles {
			roles = append(roles, *s.ResponsibleRoles[j].MarshalOscal())
		}

		rollup.Satisfies = append(rollup.Satisfies, SharedResponsibilitySatisfies{
			ControlID:          a.controlID,
			StatementID:        a.statementID,
			ByComponentUUID:    s.ByComponentId,
			SatisfiedUUID:      *s.ID,
			ResponsibilityUUID: s.ResponsibilityUuid,
			Description:        s.Description,
			ResponsibleRoles:   roles,
		})
	}

	return nil
}

// collectInheritedSharedResponsibility fills the inherits arm from the leverage projection —
// the same batched computation GET /leveraged-controls serves, so satisfaction is never
// re-derived here and the two surfaces cannot disagree.
func (h *SystemSecurityPlanHandler) collectInheritedSharedResponsibility(rollup *SharedResponsibilityRollup, sspID uuid.UUID, controlFilter string) error {
	projection, err := projectLeveragedControls(h.db, sspID)
	if err != nil {
		return err
	}
	if len(projection) == 0 {
		return nil
	}

	upstreamIDs := uniqueUUIDs(projection, func(p leveragedControlProjection) uuid.UUID { return p.Link.UpstreamSSPID })
	var upstreams []relational.SystemSecurityPlan
	if err := h.db.Preload("Metadata").Where("id IN ?", upstreamIDs).Find(&upstreams).Error; err != nil {
		return err
	}
	upstreamTitleByID := make(map[uuid.UUID]string, len(upstreams))
	for _, s := range upstreams {
		upstreamTitleByID[*s.ID] = s.Metadata.Title
	}

	for _, p := range projection {
		if controlFilter != "" && !strings.EqualFold(p.Link.ControlID, controlFilter) {
			continue
		}

		description := ""
		if p.Inherited != nil {
			description = p.Inherited.Description
		}

		rollup.Inherits = append(rollup.Inherits, SharedResponsibilityInherits{
			ControlID:        p.Link.ControlID,
			StatementID:      p.Link.StatementID,
			ByComponentUUID:  p.ByComponentID,
			InheritedUUID:    p.Link.InheritedUUID,
			ProvidedUUID:     p.Link.ProvidedUUID,
			UpstreamSSPID:    p.Link.UpstreamSSPID,
			UpstreamSSPTitle: upstreamTitleByID[p.Link.UpstreamSSPID],
			OfferingID:       p.Link.OfferingID,
			OfferingVersion:  p.Link.OfferingVersion,
			LeverageLinkID:   *p.Link.ID,
			Satisfaction:     p.Satisfaction,
			Status:           p.Link.Status,
			Description:      description,
		})
	}

	return nil
}
