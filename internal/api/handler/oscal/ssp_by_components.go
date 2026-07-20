package oscal

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// This file holds the by-component read surface and the consumer-side (Inherited/Satisfied)
// CRUD. Both were missing entirely: there were no GET routes for by-components at either
// level, so the UI could never refetch one after editing a sub-resource, and Inherited and
// Satisfied were written *only* by Subscribe — a downstream author could not mark a
// responsibility satisfied later, edit a description, attach responsible-roles, or drop a
// stale inherited entry without re-subscribing.
//
// Inherited/Satisfied are statement-level only, on purpose: they are the downstream half of
// the export -> inherit -> satisfy loop, and that loop is anchored on a statement.

// errInheritedOwnedBySubscription is returned when a delete targets an InheritedControlImplementation
// that an SSPLeverageLink still references. Such a row is owned by its subscription, not by
// the author — removing it would leave the link pointing at nothing, and both the drift
// detector and the notification path read through link.InheritedUUID. Mapped to 409, with the
// unsubscribe path as the way out. Hand-authored inherited entries (no link row) delete freely.
var errInheritedOwnedBySubscription = errors.New("inherited entry is owned by a leverage subscription; unsubscribe instead of deleting it")

// errResponsibilityNotInheritable is returned from inside the satisfied-create transaction when
// the responsibility-uuid isn't on any export this by-component inherits. It exists so the check
// can run under the subtree lock and still surface as a 400 rather than a 500.
var errResponsibilityNotInheritable = errors.New("responsibility is not inheritable by this by-component")

// errProvidedAlreadyInherited is returned when a provided-uuid is already inherited by another
// by-component in the same SSP. See the check in the inherited create for why that is ambiguous
// rather than merely redundant. Mapped to 409.
var errProvidedAlreadyInherited = errors.New("provided-uuid is already inherited in this system security plan")

// errDuplicateInheritedUUID / errDuplicateSatisfiedUUID turn a client-supplied uuid that collides
// with an existing row into a 409 instead of leaking a raw driver error as a 500. ensureBodyUUID
// accepts any well-formed uuid, so replaying a create — or copying a uuid off another
// by-component — is trivially reachable.
var errDuplicateInheritedUUID = errors.New("an inherited entry with this uuid already exists")
var errDuplicateSatisfiedUUID = errors.New("a satisfied entry with this uuid already exists")

// ensureProvidedUUIDNotAlreadyInherited enforces "one provided-uuid may be inherited only once
// per SSP". A subscription's link is reached through its inherited row, and satisfaction is
// derived from the owning by-component's satisfied set — so a second by-component inheriting the
// same provided-uuid would make "which satisfied set governs this capability" ambiguous. Nothing
// in the schema forbids it (the leverage link's uniqueIndex only stops a second SUBSCRIBE), so it
// is enforced here, across both anchoring levels AND both creation paths: the hand-authored
// inherited create and Subscribe. Guarding only one left the invariant reachable by hand-authoring
// the row first and subscribing second.
//
// tx must be the caller's transaction, holding the by-component subtree lock — checking outside it
// races the very concurrent create the lock exists to serialize.
//
// Subscribe calls this once PER ITEM, which is what catches two items in one request carrying the
// same provided-uuid — hoisting it out of that loop would resolve the SSP once and miss exactly
// that case. So it has to be cheap per call: this walks the chain in ONE query with two bind
// parameters, rather than materializing the SSP's requirement/statement/by-component id sets and
// passing them back as `IN ?` lists. Those lists are unbounded in SSP size, and `IN ?` expands to
// one bind parameter per element — the same 65535-bind ceiling allowedDownstreamSQL avoids for the
// offering allow-list and findByIDsInChunks works around in the migrator backfill. An N-item
// subscribe also re-derived those sets N times, inside the advisory lock's critical section.
//
// No CAST anywhere: ByComponent.ParentID and Statement.ImplementedRequirementId are both uuid, so
// the joins compare like types. Casting to uuid here would break the sqlite-backed unit suites.
// The parent_type literals match byComponentIDsForSSP's, which are GORM's polymorphic table names.
func ensureProvidedUUIDNotAlreadyInherited(tx *gorm.DB, sspID uuid.UUID, providedUUID uuid.UUID) error {
	const dupeSQL = `
		SELECT COUNT(*)
		FROM inherited_control_implementations i
		JOIN by_components bc ON bc.id = i.by_component_id
		LEFT JOIN statements s
			ON bc.parent_type = 'statements' AND s.id = bc.parent_id
		JOIN implemented_requirements ir
			ON ir.id = CASE WHEN bc.parent_type = 'statements'
			                THEN s.implemented_requirement_id
			                ELSE bc.parent_id END
		JOIN control_implementations ci ON ci.id = ir.control_implementation_id
		WHERE ci.system_security_plan_id = ? AND i.provided_uuid = ?`

	var dupe int64
	if err := tx.Raw(dupeSQL, sspID, providedUUID).Scan(&dupe).Error; err != nil {
		return err
	}
	if dupe > 0 {
		return errProvidedAlreadyInherited
	}
	return nil
}

// assertInheritedNotSubscribed enforces errInheritedOwnedBySubscription over a set of inherited
// ids. Both delete paths — the sub-resource route and the by-component cascade — must apply the
// same rule; guarding only one left the invariant bypassable by deleting the parent, and the two
// copies had already drifted into different queries.
func assertInheritedNotSubscribed(tx *gorm.DB, inheritedIDs []uuid.UUID) error {
	if len(inheritedIDs) == 0 {
		return nil
	}
	var linkCount int64
	if err := tx.Model(&relational.SSPLeverageLink{}).
		Where("inherited_uuid IN ?", inheritedIDs).
		Count(&linkCount).Error; err != nil {
		return err
	}
	if linkCount > 0 {
		return errInheritedOwnedBySubscription
	}
	return nil
}

// GetImplementedRequirementByComponent godoc
//
//	@Summary		Get a by-component within an implemented requirement
//	@Description	Deprecated: requirement-anchored by-components are legacy — read-only here so
//	@Description	the UI can display and wind them down. New by-components must be created
//	@Description	against a statement.
//	@Description
//	@Description	Returns the by-component with its export (including provided and
//	@Description	responsibilities), inherited and satisfied entries, responsible-roles and
//	@Description	implementation-status.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId} [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementByComponent(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponent(ctx, bc)
}

// GetImplementedRequirementStatementByComponent godoc
//
//	@Summary		Get a by-component within a statement
//	@Description	Returns the by-component with its export (including provided and
//	@Description	responsibilities), inherited and satisfied entries, responsible-roles and
//	@Description	implementation-status — everything needed to refetch one by-component after
//	@Description	editing any of its sub-resources.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			stmtId			path		string	true	"Statement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId} [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementStatementByComponent(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponent(ctx, bc)
}

// getByComponent renders one already-resolved by-component with every subtree preloaded.
func (h *SystemSecurityPlanHandler) getByComponent(ctx echo.Context, bc *relational.ByComponent) error {
	loaded, err := h.reloadByComponent(*bc.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("by-component not found")))
		}
		h.sugar.Errorw("Failed to reload by-component", "byComponentId", *bc.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]{Data: *loaded.MarshalOscal()})
}

// GetImplementedRequirementStatementByComponents godoc
//
//	@Summary		List the by-components on a statement
//	@Description	Returns every by-component attached to the statement, each with its export
//	@Description	(including provided and responsibilities), inherited and satisfied entries,
//	@Description	responsible-roles and implementation-status.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id		path		string	true	"SSP ID"
//	@Param			reqId	path		string	true	"Requirement ID"
//	@Param			stmtId	path		string	true	"Statement ID"
//	@Success		200		{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ByComponent]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementStatementByComponents(ctx echo.Context) error {
	stmt, ok := h.resolveStatement(ctx)
	if !ok {
		return nil
	}

	var byComponents []relational.ByComponent
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Preload("Inherited.ResponsibleRoles.Parties").
		Preload("Satisfied.ResponsibleRoles.Parties").
		Preload("Export.Provided.ResponsibleRoles.Parties").
		Preload("Export.Responsibilities.ResponsibleRoles.Parties").
		Where("parent_id = ? AND parent_type = ?", stmt.ID, "statements").
		Order("id ASC").
		Find(&byComponents).Error; err != nil {
		h.sugar.Errorf("Failed to list by-components: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	result := make([]oscalTypes_1_1_3.ByComponent, 0, len(byComponents))
	for i := range byComponents {
		result = append(result, *byComponents[i].MarshalOscal())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ByComponent]{Data: result})
}

// resolveStatement parses and verifies a statement belongs to a requirement of the SSP named
// in the path, writing the appropriate error response and returning ok=false on any failure —
// the statement-level sibling of resolveByComponentForStatement, for routes that address a
// statement rather than one by-component under it.
func (h *SystemSecurityPlanHandler) resolveStatement(ctx echo.Context) (stmt *relational.Statement, ok bool) {
	sspID, reqID, stmtID, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid statement path params", "error", err)
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
			return nil, false
		}
		h.sugar.Errorw("Failed to get ssp", "sspId", sspID, "error", err)
		_ = ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		return nil, false
	}

	var req relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).
		First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("requirement not found")))
			return nil, false
		}
		h.sugar.Errorw("Failed to get implemented requirement", "reqId", reqID, "error", err)
		_ = ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		return nil, false
	}

	var found relational.Statement
	if err := h.db.Where("id = ? AND implemented_requirement_id = ?", stmtID, req.ID).
		First(&found).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("statement not found")))
			return nil, false
		}
		h.sugar.Errorw("Failed to get statement", "stmtId", stmtID, "error", err)
		_ = ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		return nil, false
	}

	return &found, true
}

// DeleteImplementedRequirementByComponent godoc
//
//	@Summary		Delete a by-component within an implemented requirement
//	@Description	Deprecated: requirement-anchored by-components are legacy. This delete exists
//	@Description	purely so legacy and orphaned requirement-anchored rows can be wound down —
//	@Description	there is deliberately no requirement-level POST to create new ones.
//	@Description
//	@Description	Cascades exactly like the statement-level delete: the by-component's own
//	@Description	responsible-roles, its inherited and satisfied entries (each with their
//	@Description	responsible-roles), and its export with nested provided/responsibilities are all
//	@Description	removed, along with the responsible_role_parties join rows.
//	@Description
//	@Description	Returns 409 if any of the by-component's inherited entries is owned by a
//	@Description	leverage subscription — deleting the parent must not be a way around the same
//	@Description	guard the inherited sub-resource DELETE enforces. Unsubscribe first.
//	@Tags			System Security Plans
//	@Param			id				path	string	true	"SSP ID"
//	@Param			reqId			path	string	true	"Requirement ID"
//	@Param			byComponentId	path	string	true	"By-Component ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		409				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementByComponent(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		return deleteByComponentCascade(tx, *bc.ID)
	}); err != nil {
		if errors.Is(err, errInheritedOwnedBySubscription) {
			return ctx.JSON(http.StatusConflict, api.NewError(err))
		}
		h.sugar.Errorf("Failed to delete by-component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// getByComponentExportProvided lists the Provided entries under an already-resolved
// by-component's Export.
func (h *SystemSecurityPlanHandler) getByComponentExportProvided(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	var provided []relational.ProvidedControlImplementation
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Where("export_id = ?", export.ID).
		Order("id ASC").
		Find(&provided).Error; err != nil {
		h.sugar.Errorw("Failed to list export provided", "exportId", export.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	result := make([]oscalTypes_1_1_3.ProvidedControlImplementation, 0, len(provided))
	for i := range provided {
		result = append(result, *provided[i].MarshalOscal())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ProvidedControlImplementation]{Data: result})
}

// getByComponentExportResponsibilities lists the ControlImplementationResponsibility entries
// under an already-resolved by-component's Export.
func (h *SystemSecurityPlanHandler) getByComponentExportResponsibilities(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	var responsibilities []relational.ControlImplementationResponsibility
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Where("export_id = ?", export.ID).
		Order("id ASC").
		Find(&responsibilities).Error; err != nil {
		h.sugar.Errorw("Failed to list export responsibilities", "exportId", export.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	result := make([]oscalTypes_1_1_3.ControlImplementationResponsibility, 0, len(responsibilities))
	for i := range responsibilities {
		result = append(result, *responsibilities[i].MarshalOscal())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]{Data: result})
}

// GetImplementedRequirementByComponentExportProvided godoc
//
//	@Summary		List the provided entries on a control-level by-component's export
//	@Description	Deprecated: use the statement-level equivalent. Requirement-anchored exports are legacy.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ProvidedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/provided [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponentExportProvided(ctx, bc)
}

// GetImplementedRequirementByComponentExportResponsibilities godoc
//
//	@Summary		List the responsibility entries on a control-level by-component's export
//	@Description	Deprecated: use the statement-level equivalent. Requirement-anchored exports are legacy.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/responsibilities [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementByComponentExportResponsibilities(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponentExportResponsibilities(ctx, bc)
}

// GetImplementedRequirementStatementByComponentExportProvided godoc
//
//	@Summary		List the provided entries on a statement-level by-component's export
//	@Description	Retrieves every ProvidedControlImplementation under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			stmtId			path		string	true	"Statement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ProvidedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/provided [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementStatementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponentExportProvided(ctx, bc)
}

// GetImplementedRequirementStatementByComponentExportResponsibilities godoc
//
//	@Summary		List the responsibility entries on a statement-level by-component's export
//	@Description	Retrieves every ControlImplementationResponsibility under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			stmtId			path		string	true	"Statement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/responsibilities [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementStatementByComponentExportResponsibilities(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponentExportResponsibilities(ctx, bc)
}

// GetImplementedRequirementStatementByComponentInherited godoc
//
//	@Summary		List the inherited control implementations on a statement-level by-component
//	@Description	Retrieves what this system consumes from an upstream under this statement.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			stmtId			path		string	true	"Statement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.InheritedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/inherited [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementStatementByComponentInherited(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	var inherited []relational.InheritedControlImplementation
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Where("by_component_id = ?", bc.ID).
		Order("id ASC").
		Find(&inherited).Error; err != nil {
		h.sugar.Errorw("Failed to list inherited control implementations", "byComponentId", bc.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	result := make([]oscalTypes_1_1_3.InheritedControlImplementation, 0, len(inherited))
	for i := range inherited {
		result = append(result, *inherited[i].MarshalOscal())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.InheritedControlImplementation]{Data: result})
}

// CreateImplementedRequirementStatementByComponentInherited godoc
//
//	@Summary		Create an inherited control implementation on a statement-level by-component
//	@Description	Records that this system consumes an upstream's provided capability under this
//	@Description	statement. Hand-authored entries carry no leverage link; entries created by
//	@Description	Subscribe do, and are protected from deletion (409) while that subscription lives.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string											true	"SSP ID"
//	@Param			reqId			path		string											true	"Requirement ID"
//	@Param			stmtId			path		string											true	"Statement ID"
//	@Param			byComponentId	path		string											true	"By-Component ID"
//	@Param			inherited		body		oscalTypes_1_1_3.InheritedControlImplementation	true	"Inherited data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		409				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/inherited [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatementByComponentInherited(ctx echo.Context) error {
	sspID, _, _, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	var oscalInherited oscalTypes_1_1_3.InheritedControlImplementation
	if err := ctx.Bind(&oscalInherited); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ensureBodyUUID(&oscalInherited.UUID); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if oscalInherited.ProvidedUuid == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("provided-uuid is required")))
	}
	providedUUID, err := uuid.Parse(oscalInherited.ProvidedUuid)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("provided-uuid must be a valid UUID")))
	}
	// Well-formed is not enough: it has to resolve. An inherited row pointing at a
	// ProvidedControlImplementation that doesn't exist is inert — inheritableResponsibilities
	// resolves nothing for it, so no satisfied entry can ever be accepted against it — yet it
	// still reads back as a real inherited capability. Same class of defect the offering-item
	// coherence check rejects, one layer down. The satisfied POST already validates its
	// responsibility-uuid this way.
	//
	// This lookup is GLOBAL BY DESIGN. It asks only whether the provided-uuid exists anywhere in
	// the database, and deliberately does NOT apply isDownstreamAllowed. Subscribe does enforce
	// the allow-list — it returns 403 (errDownstreamNotAllowed) when the downstream is not
	// allow-listed for the offering — so the asymmetry between the two paths is a decision, not
	// an oversight: a hand-authored inherited row is the author's own assertion about their own
	// system, and holding it to the subscription trust boundary would block recording inheritance
	// that is real but not modelled as a subscription.
	//
	// What that exposes, stated plainly: a caller with create rights on their own SSP gets a
	// 201-vs-400 existence oracle over every provided-uuid in the installation, and can make
	// inheritableResponsibilities resolve the responsibility set of an upstream they have no
	// relationship with.
	//
	// What it does NOT expose: this path creates no SSPLeverageLink, so nothing recorded here
	// reaches the drift detector or the inherits arm of the rollup. The effect stops at this
	// SSP's own hand-authored rows.
	//
	// Revisit if provided-uuid existence ever becomes confidential: at that point scope this
	// lookup to provided-uuids reachable through an offering this SSP is allow-listed for.
	if err := h.db.First(&relational.ProvidedControlImplementation{}, "id = ?", providedUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
				"provided-uuid %q does not resolve to a provided control implementation", providedUUID)))
		}
		h.sugar.Errorf("Failed to resolve provided control implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	relInherited := &relational.InheritedControlImplementation{}
	relInherited.UnmarshalOscal(oscalInherited)
	relInherited.ByComponentId = *bc.ID

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		// Same advisory-lock guard the Export create uses: nothing in the schema stops two
		// concurrent creates from racing on the same by-component. No satisfaction re-derivation
		// belongs here — creating an inherited row changes what is inheritable, not what is
		// satisfied — so the lock is purely to serialize concurrent creates against the
		// already-inherited check below.
		if err := lockByComponentSubtreeWrite(tx, *bc.ID); err != nil {
			return err
		}
		if err := ensureProvidedUUIDNotAlreadyInherited(tx, sspID, providedUUID); err != nil {
			return err
		}
		return tx.Create(relInherited).Error
	}); err != nil {
		if errors.Is(err, errProvidedAlreadyInherited) {
			return ctx.JSON(http.StatusConflict, api.NewError(fmt.Errorf(
				"provided-uuid %q is already inherited elsewhere in this system security plan", providedUUID)))
		}
		if isUniqueViolation(err) {
			return ctx.JSON(http.StatusConflict, api.NewError(errDuplicateInheritedUUID))
		}
		h.sugar.Errorf("Failed to create inherited control implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// The transaction above has COMMITTED. A failure to re-read the row must not be reported as
	// a 5xx: the resource exists, and a client retrying what looked like a failed create would
	// either duplicate it or bounce off the 409. The reload only re-fetches what we already hold
	// — UnmarshalOscal populated ResponsibleRoles and their Parties from the request body, which
	// is what MarshalOscal renders — so the in-memory value is the same resource. Log loudly and
	// serve it rather than downgrading a committed write.
	created, err := h.reloadInherited(*relInherited.ID)
	if err != nil {
		h.sugar.Errorw("Failed to reload inherited control implementation after a committed create; serving the in-memory value",
			"inheritedId", *relInherited.ID, "byComponentId", *bc.ID, "error", err)
		created = relInherited
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]{Data: *created.MarshalOscal()})
}

// UpdateImplementedRequirementStatementByComponentInherited godoc
//
//	@Summary		Update an inherited control implementation on a statement-level by-component
//	@Description	Metadata only — description, props, links and responsible-roles. provided-uuid
//	@Description	is immutable and a body attempting to change it is rejected with 400: it is the
//	@Description	identity the leverage link and the drift detector join on.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string											true	"SSP ID"
//	@Param			reqId			path		string											true	"Requirement ID"
//	@Param			stmtId			path		string											true	"Statement ID"
//	@Param			byComponentId	path		string											true	"By-Component ID"
//	@Param			inheritedId		path		string											true	"Inherited ID"
//	@Param			inherited		body		oscalTypes_1_1_3.InheritedControlImplementation	true	"Inherited data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/inherited/{inheritedId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatementByComponentInherited(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	inheritedID, err := uuid.Parse(ctx.Param("inheritedId"))
	if err != nil {
		h.sugar.Warnw("Invalid inherited id", "inheritedId", ctx.Param("inheritedId"), "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existing relational.InheritedControlImplementation
	if err := h.db.Where("id = ? AND by_component_id = ?", inheritedID, bc.ID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("inherited entry not found")))
		}
		h.sugar.Errorw("Failed to get inherited control implementation", "inheritedId", inheritedID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	var oscalInherited oscalTypes_1_1_3.InheritedControlImplementation
	if err := ctx.Bind(&oscalInherited); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	// Compared as parsed uuid VALUES, not strings: uuid.UUID.String() always emits lowercase,
	// but RFC 4122 permits uppercase and plenty of JSON/UI toolchains preserve whatever casing
	// they were handed. A client round-tripping a GET into a PUT with a canonically-uppercase
	// provided-uuid is sending a semantically identical value and must not be told it tried to
	// mutate an immutable field. An empty string still means "omitted, leave unchanged"; a
	// malformed value deliberately falls into the same 400.
	if s := oscalInherited.ProvidedUuid; s != "" {
		parsed, err := uuid.Parse(s)
		if err != nil || parsed != existing.ProvidedUuid {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
				"provided-uuid is immutable: it is the identity the leverage link and drift detector join on")))
		}
	}
	// Echo back the stored identities so UnmarshalOscal's MustParse can't panic on a body
	// that legitimately omits them.
	oscalInherited.UUID = existing.ID.String()
	oscalInherited.ProvidedUuid = existing.ProvidedUuid.String()

	parsed := &relational.InheritedControlImplementation{}
	parsed.UnmarshalOscal(oscalInherited)

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&relational.InheritedControlImplementation{}).
			Where("id = ?", existing.ID).
			Updates(map[string]any{
				"description": parsed.Description,
				"props":       parsed.Props,
				"links":       parsed.Links,
			}).Error; err != nil {
			return err
		}
		return replaceResponsibleRoles(tx, &existing, *existing.ID, parsed.ResponsibleRoles)
	}); err != nil {
		h.sugar.Errorf("Failed to update inherited control implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	updated, err := h.reloadInherited(*existing.ID)
	if err != nil {
		h.sugar.Errorw("Failed to reload inherited control implementation", "inheritedId", *existing.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]{Data: *updated.MarshalOscal()})
}

// DeleteImplementedRequirementStatementByComponentInherited godoc
//
//	@Summary		Delete an inherited control implementation on a statement-level by-component
//	@Description	Hand-authored entries delete freely. An entry created by a subscription is owned
//	@Description	by that subscription — an SSPLeverageLink still references it, and both drift
//	@Description	detection and notifications read through that reference — so deleting it returns
//	@Description	409; unsubscribe instead.
//	@Tags			System Security Plans
//	@Param			id				path	string	true	"SSP ID"
//	@Param			reqId			path	string	true	"Requirement ID"
//	@Param			stmtId			path	string	true	"Statement ID"
//	@Param			byComponentId	path	string	true	"By-Component ID"
//	@Param			inheritedId		path	string	true	"Inherited ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		409				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/inherited/{inheritedId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementStatementByComponentInherited(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	inheritedID, err := uuid.Parse(ctx.Param("inheritedId"))
	if err != nil {
		h.sugar.Warnw("Invalid inherited id", "inheritedId", ctx.Param("inheritedId"), "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existing relational.InheritedControlImplementation
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Where("id = ? AND by_component_id = ?", inheritedID, bc.ID).
		First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("inherited entry not found")))
		}
		h.sugar.Errorw("Failed to get inherited control implementation", "inheritedId", inheritedID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		// Without the lock the count below is a pre-check-then-delete: a concurrent Subscribe can
		// create a link for this row between the two, leaving link.InheritedUUID dangling. This
		// path never calls resyncLeverageSatisfaction, so nothing takes the lock on its behalf.
		if err := lockByComponentSubtreeWrite(tx, existing.ByComponentId); err != nil {
			return err
		}
		if err := assertInheritedNotSubscribed(tx, []uuid.UUID{*existing.ID}); err != nil {
			return err
		}

		if err := deleteResponsibleRoles(tx, existing.ResponsibleRoles); err != nil {
			return err
		}
		return tx.Delete(&existing).Error
	}); err != nil {
		if errors.Is(err, errInheritedOwnedBySubscription) {
			return ctx.JSON(http.StatusConflict, api.NewError(err))
		}
		h.sugar.Errorf("Failed to delete inherited control implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetImplementedRequirementStatementByComponentSatisfied godoc
//
//	@Summary		List the satisfied responsibilities on a statement-level by-component
//	@Description	Retrieves how this system discharges its upstream's responsibilities under this statement.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			stmtId			path		string	true	"Statement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/satisfied [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementStatementByComponentSatisfied(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	var satisfied []relational.SatisfiedControlImplementationResponsibility
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Where("by_component_id = ?", bc.ID).
		Order("id ASC").
		Find(&satisfied).Error; err != nil {
		h.sugar.Errorw("Failed to list satisfied responsibilities", "byComponentId", bc.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	result := make([]oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility, 0, len(satisfied))
	for i := range satisfied {
		result = append(result, *satisfied[i].MarshalOscal())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]{Data: result})
}

// CreateImplementedRequirementStatementByComponentSatisfied godoc
//
//	@Summary		Create a satisfied responsibility on a statement-level by-component
//	@Description	Records that this system discharges one of its upstream's responsibilities. The
//	@Description	responsibility-uuid must resolve to a ControlImplementationResponsibility on an
//	@Description	Export this by-component actually inherits from (400 otherwise). If the owning
//	@Description	SSPLeverageLink exists, its cached Satisfaction is re-derived in the same
//	@Description	transaction, so partial can flip to full atomically with the write that causes it.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string															true	"SSP ID"
//	@Param			reqId			path		string															true	"Requirement ID"
//	@Param			stmtId			path		string															true	"Statement ID"
//	@Param			byComponentId	path		string															true	"By-Component ID"
//	@Param			satisfied		body		oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility	true	"Satisfied data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		409				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/satisfied [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatementByComponentSatisfied(ctx echo.Context) error {
	sspID, _, _, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	var oscalSatisfied oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility
	if err := ctx.Bind(&oscalSatisfied); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ensureBodyUUID(&oscalSatisfied.UUID); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	responsibilityUUID, err := uuid.Parse(oscalSatisfied.ResponsibilityUuid)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("responsibility-uuid must be a valid UUID")))
	}

	relSatisfied := &relational.SatisfiedControlImplementationResponsibility{}
	relSatisfied.UnmarshalOscal(oscalSatisfied)
	relSatisfied.ByComponentId = *bc.ID

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := lockByComponentSubtreeWrite(tx, *bc.ID); err != nil {
			return err
		}
		// Inside the tx and after the lock: read on h.db before either, and a concurrent
		// inherited DELETE could retire the responsibility between the check and the insert,
		// leaving a satisfied row that is no longer inheritable and can never be re-derived away.
		inheritable, err := inheritableResponsibilities(tx, *bc.ID)
		if err != nil {
			return err
		}
		if !inheritable[responsibilityUUID] {
			return errResponsibilityNotInheritable
		}
		if err := tx.Create(relSatisfied).Error; err != nil {
			return err
		}
		return resyncLeverageSatisfaction(tx, sspID, *bc.ID)
	}); err != nil {
		if errors.Is(err, errResponsibilityNotInheritable) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
				"responsibility-uuid %q is not a responsibility on any export this by-component inherits from", responsibilityUUID)))
		}
		if isUniqueViolation(err) {
			return ctx.JSON(http.StatusConflict, api.NewError(errDuplicateSatisfiedUUID))
		}
		h.sugar.Errorf("Failed to create satisfied responsibility: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Committed already — same reasoning as the inherited create above: a post-commit reload
	// failure must not become a 5xx that invites a duplicate-creating retry.
	created, err := h.reloadSatisfied(*relSatisfied.ID)
	if err != nil {
		h.sugar.Errorw("Failed to reload satisfied responsibility after a committed create; serving the in-memory value",
			"satisfiedId", *relSatisfied.ID, "byComponentId", *bc.ID, "error", err)
		created = relSatisfied
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]{Data: *created.MarshalOscal()})
}

// UpdateImplementedRequirementStatementByComponentSatisfied godoc
//
//	@Summary		Update a satisfied responsibility on a statement-level by-component
//	@Description	Metadata only — description, remarks, props, links and responsible-roles.
//	@Description	responsibility-uuid is immutable and a body attempting to change it is rejected
//	@Description	with 400: it is what deriveSatisfaction and the drift detector match on. Because
//	@Description	the identity can't change, the owning link's Satisfaction cannot change either,
//	@Description	so no re-derivation is needed here.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string															true	"SSP ID"
//	@Param			reqId			path		string															true	"Requirement ID"
//	@Param			stmtId			path		string															true	"Statement ID"
//	@Param			byComponentId	path		string															true	"By-Component ID"
//	@Param			satisfiedId		path		string															true	"Satisfied ID"
//	@Param			satisfied		body		oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility	true	"Satisfied data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/satisfied/{satisfiedId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatementByComponentSatisfied(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	satisfiedID, err := uuid.Parse(ctx.Param("satisfiedId"))
	if err != nil {
		h.sugar.Warnw("Invalid satisfied id", "satisfiedId", ctx.Param("satisfiedId"), "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existing relational.SatisfiedControlImplementationResponsibility
	if err := h.db.Where("id = ? AND by_component_id = ?", satisfiedID, bc.ID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("satisfied entry not found")))
		}
		h.sugar.Errorw("Failed to get satisfied responsibility", "satisfiedId", satisfiedID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	var oscalSatisfied oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility
	if err := ctx.Bind(&oscalSatisfied); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	// Parsed-value comparison for the same reason as provided-uuid on the inherited PUT: an
	// uppercase round-trip of the stored uuid is the same uuid. Empty stays "omitted, leave
	// unchanged"; malformed falls into the same 400.
	if s := oscalSatisfied.ResponsibilityUuid; s != "" {
		parsed, err := uuid.Parse(s)
		if err != nil || parsed != existing.ResponsibilityUuid {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
				"responsibility-uuid is immutable: it is the identity satisfaction derivation and the drift detector join on")))
		}
	}
	oscalSatisfied.UUID = existing.ID.String()
	oscalSatisfied.ResponsibilityUuid = existing.ResponsibilityUuid.String()

	parsed := &relational.SatisfiedControlImplementationResponsibility{}
	parsed.UnmarshalOscal(oscalSatisfied)

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&relational.SatisfiedControlImplementationResponsibility{}).
			Where("id = ?", existing.ID).
			Updates(map[string]any{
				"description": parsed.Description,
				"remarks":     parsed.Remarks,
				"props":       parsed.Props,
				"links":       parsed.Links,
			}).Error; err != nil {
			return err
		}
		return replaceResponsibleRoles(tx, &existing, *existing.ID, parsed.ResponsibleRoles)
	}); err != nil {
		h.sugar.Errorf("Failed to update satisfied responsibility: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	updated, err := h.reloadSatisfied(*existing.ID)
	if err != nil {
		h.sugar.Errorw("Failed to reload satisfied responsibility", "satisfiedId", *existing.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]{Data: *updated.MarshalOscal()})
}

// DeleteImplementedRequirementStatementByComponentSatisfied godoc
//
//	@Summary		Delete a satisfied responsibility on a statement-level by-component
//	@Description	Removes the entry and, in the same transaction, re-derives the owning
//	@Description	SSPLeverageLink's cached Satisfaction — so dropping the last satisfied entry
//	@Description	flips full back to partial atomically rather than leaving the link's bookkeeping
//	@Description	stale for the drift detector to read.
//	@Tags			System Security Plans
//	@Param			id				path	string	true	"SSP ID"
//	@Param			reqId			path	string	true	"Requirement ID"
//	@Param			stmtId			path	string	true	"Statement ID"
//	@Param			byComponentId	path	string	true	"By-Component ID"
//	@Param			satisfiedId		path	string	true	"Satisfied ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/satisfied/{satisfiedId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementStatementByComponentSatisfied(ctx echo.Context) error {
	sspID, _, _, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}

	satisfiedID, err := uuid.Parse(ctx.Param("satisfiedId"))
	if err != nil {
		h.sugar.Warnw("Invalid satisfied id", "satisfiedId", ctx.Param("satisfiedId"), "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existing relational.SatisfiedControlImplementationResponsibility
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Where("id = ? AND by_component_id = ?", satisfiedID, bc.ID).
		First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("satisfied entry not found")))
		}
		h.sugar.Errorw("Failed to get satisfied responsibility", "satisfiedId", satisfiedID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		// Same lock the satisfied CREATE takes, and for the same reason: this transaction is a
		// read-modify-write over the by-component's satisfied set (delete a row, then re-derive
		// the owning link's Satisfaction from what remains). If only the create side locked, a
		// concurrent create and delete would each compute satisfaction from a snapshot taken
		// before the other's write was visible, and the second UPDATE would overwrite the first
		// with a stale value.
		if err := lockByComponentSubtreeWrite(tx, *bc.ID); err != nil {
			return err
		}
		if err := deleteResponsibleRoles(tx, existing.ResponsibleRoles); err != nil {
			return err
		}
		if err := tx.Delete(&existing).Error; err != nil {
			return err
		}
		return resyncLeverageSatisfaction(tx, sspID, *bc.ID)
	}); err != nil {
		h.sugar.Errorf("Failed to delete satisfied responsibility: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// inheritableResponsibilities is the set of upstream responsibility uuids a by-component may
// legitimately claim to satisfy: the responsibilities on the Exports behind the provided-uuids
// this by-component actually inherits. Scoped by (export_id, provided_uuid) via
// bulkResolveUpstreamResponsibilities, because provided-uuid values are only unique within one
// upstream's Export — a provided_uuid-only match could pick up a same-valued responsibility
// from an unrelated Export.
//
// Takes the caller's db handle so a writer can run it inside its transaction, after taking
// lockByComponentSubtreeWrite: the answer is only trustworthy for a write if the inherited set
// it reads cannot change between the check and the insert.
func inheritableResponsibilities(db *gorm.DB, byComponentID uuid.UUID) (map[uuid.UUID]bool, error) {
	var inherited []relational.InheritedControlImplementation
	if err := db.Where("by_component_id = ?", byComponentID).Find(&inherited).Error; err != nil {
		return nil, err
	}

	providedUUIDs := uniqueUUIDs(inherited, func(i relational.InheritedControlImplementation) uuid.UUID { return i.ProvidedUuid })
	byProvided, err := bulkResolveUpstreamResponsibilities(db, providedUUIDs)
	if err != nil {
		return nil, err
	}

	allowed := make(map[uuid.UUID]bool)
	for _, responsibilities := range byProvided {
		for _, r := range responsibilities {
			allowed[r.ResponsibilityUUID] = true
		}
	}
	return allowed, nil
}

// resyncLeverageSatisfaction re-derives the cached Satisfaction on every SSPLeverageLink that
// owns an Inherited row on this by-component, after its satisfied set changed.
//
// LeveragedControls recomputes satisfaction live, so the stored value is bookkeeping — but the
// drift detector and the notification path read it, so it must not rot. Links are found by
// inherited_uuid, NOT by (downstream_ssp_id, provided_uuid). That pair carries a unique index on
// ssp_leverage_links, so it identifies at most one link — but it does not identify which
// by-component's satisfied set governs that link. Nothing constrains InheritedControlImplementation,
// so two by-components in one SSP can each hold an inherited row for the same provided-uuid while
// only one link exists; keying on the pair would let this by-component's satisfied set overwrite a
// sibling's link. inherited_uuid is unambiguous: it names the exact row the link was created for.
// A hand-authored inherited entry has no link and is skipped silently.
//
// Runs inside the caller's transaction so the satisfied write and the satisfaction it implies
// commit together.
//
// It takes lockByComponentSubtreeWrite itself rather than trusting every caller to remember. This
// function IS the read-modify-write the lock exists to serialize (it reads the satisfied set and
// UPDATEs link satisfaction with a value computed in Go), and "every writer must take the lock" is
// an invariant that has already been half-missed twice — the satisfied DELETE, then Subscribe.
// Postgres advisory locks are re-entrant within a transaction, so callers that correctly take it
// earlier (to cover their own writes too, which they should) pay nothing for taking it twice.
func resyncLeverageSatisfaction(tx *gorm.DB, downstreamSSPID, byComponentID uuid.UUID) error {
	if err := lockByComponentSubtreeWrite(tx, byComponentID); err != nil {
		return err
	}

	var inherited []relational.InheritedControlImplementation
	if err := tx.Where("by_component_id = ?", byComponentID).Find(&inherited).Error; err != nil {
		return err
	}
	if len(inherited) == 0 {
		return nil
	}

	var satisfiedRows []relational.SatisfiedControlImplementationResponsibility
	if err := tx.Where("by_component_id = ?", byComponentID).Find(&satisfiedRows).Error; err != nil {
		return err
	}
	// deriveSatisfaction only asks whether each *upstream* responsibility is covered, so
	// satisfied rows belonging to a sibling inherited entry on the same by-component are
	// simply never consulted — one set is safe to share across all of them.
	satisfiedUUIDs := make(map[uuid.UUID]bool, len(satisfiedRows))
	for _, s := range satisfiedRows {
		satisfiedUUIDs[s.ResponsibilityUuid] = true
	}

	providedUUIDs := uniqueUUIDs(inherited, func(i relational.InheritedControlImplementation) uuid.UUID { return i.ProvidedUuid })
	fullSetByProvided, err := bulkResolveUpstreamResponsibilities(tx, providedUUIDs)
	if err != nil {
		return err
	}

	// The inherited row names the provided-impl its link is derived from; the link is reached
	// through the row's id, so a sibling by-component holding the same provided-uuid is untouched.
	providedByInherited := make(map[uuid.UUID]uuid.UUID, len(inherited))
	inheritedIDs := make([]uuid.UUID, 0, len(inherited))
	for _, i := range inherited {
		providedByInherited[*i.ID] = i.ProvidedUuid
		inheritedIDs = append(inheritedIDs, *i.ID)
	}

	var links []relational.SSPLeverageLink
	if err := tx.Where("downstream_ssp_id = ? AND inherited_uuid IN ?", downstreamSSPID, inheritedIDs).
		Find(&links).Error; err != nil {
		return err
	}

	for _, link := range links {
		providedUUID, ok := providedByInherited[link.InheritedUUID]
		if !ok {
			continue
		}
		satisfaction, _ := deriveSatisfaction(fullSetByProvided[providedUUID], satisfiedUUIDs)
		if satisfaction == link.Satisfaction {
			continue
		}
		if err := tx.Model(&relational.SSPLeverageLink{}).
			Where("id = ?", link.ID).
			Update("satisfaction", satisfaction).Error; err != nil {
			return err
		}
	}
	return nil
}

// ensureBodyUUID fills in a missing uuid on a create body and rejects a malformed one. The
// OSCAL Unmarshal* helpers MustParse their uuid field, so without this a body omitting it
// panics into a 500 instead of returning a 400.
func ensureBodyUUID(id *string) error {
	if *id == "" {
		*id = uuid.New().String()
		return nil
	}
	if _, err := uuid.Parse(*id); err != nil {
		return fmt.Errorf("uuid must be a valid UUID")
	}
	return nil
}

func (h *SystemSecurityPlanHandler) reloadInherited(id uuid.UUID) (*relational.InheritedControlImplementation, error) {
	var row relational.InheritedControlImplementation
	err := h.db.Preload("ResponsibleRoles.Parties").First(&row, "id = ?", id).Error
	return &row, err
}

func (h *SystemSecurityPlanHandler) reloadSatisfied(id uuid.UUID) (*relational.SatisfiedControlImplementationResponsibility, error) {
	var row relational.SatisfiedControlImplementationResponsibility
	err := h.db.Preload("ResponsibleRoles.Parties").First(&row, "id = ?", id).Error
	return &row, err
}
