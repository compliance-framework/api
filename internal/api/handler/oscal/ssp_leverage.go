package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
)

// thisSystemComponentType is the OSCAL convention for a placeholder component
// representing the system itself, used to anchor by-components that aren't tied to any
// specific local component (e.g. purely-inherited capabilities). There's no existing Go
// constant for this — it only appears in JSON test fixtures — so it's declared here.
const thisSystemComponentType = "this-system"

// errDuplicateLeverageLink signals a UNIQUE(downstream_ssp_id, provided_uuid) violation
// caught inside the subscribe transaction — a concurrent request racing the same insert
// past the pre-check earlier in Subscribe. Mapped to 409, same as the pre-check's own
// (non-racy) duplicate detection.
var errDuplicateLeverageLink = errors.New("already subscribed to this provided-uuid")

// errLeverageLinkNoLongerDrifted signals that ReAttest's pre-check (link.Status ==
// Drifted, read before the transaction opened) is now stale by the time the
// transaction's own update runs — a concurrent re-attest already cleared it, or a new
// drift trigger landed in between. Mapped to 409: retrying with a fresh read is the
// correct client action, not treated as a 500.
var errLeverageLinkNoLongerDrifted = errors.New("leverage link is no longer drifted")

// errDownstreamNotAllowed signals that the offering's allow-list (BCH-1342) rejects
// downstreamSSPID. Checked inside the subscribe transaction (via tx, not h.db) so the
// allow-list read and the write it gates are atomic — reading it before the transaction
// opened would let a concurrent allow-list change race the write undetected. Mapped to
// 403, same as the original pre-transaction check.
var errDownstreamNotAllowed = errors.New("downstream not allow-listed for this offering")

// isUniqueViolation reports whether err is a Postgres unique-constraint violation. GORM's
// ErrDuplicatedKey translation is unreliable here (same issue noted in
// internal/api/handler/groups.go's isUniqueViolation), so the driver code is inspected
// directly.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// upstreamResponsibility is the minimal shape both the catalog exposure (BCH-1338 task
// 004) and the subscribe handler (task 005) need: enough to let a downstream subscriber
// pick specific responsibility UUIDs to satisfy, and to compute full/partial coverage.
type upstreamResponsibility struct {
	ResponsibilityUUID uuid.UUID `json:"responsibilityUuid"`
	Description        string    `json:"description"`
}

// resolveUpstreamResponsibilities finds every ControlImplementationResponsibility that
// responsibility-maps to the ProvidedControlImplementation identified by providedUUID.
// A thin single-item wrapper over bulkResolveUpstreamResponsibilities — see that function
// for the lookup strategy.
func resolveUpstreamResponsibilities(db *gorm.DB, providedUUID uuid.UUID) ([]upstreamResponsibility, error) {
	byProvided, err := bulkResolveUpstreamResponsibilities(db, []uuid.UUID{providedUUID})
	if err != nil {
		return nil, err
	}
	return byProvided[providedUUID], nil
}

// bulkResolveUpstreamResponsibilities is the batched form of resolveUpstreamResponsibilities:
// two queries total regardless of how many providedUUIDs are requested, rather than two
// queries per item (the catalog list and the leveraged-controls projection each resolve
// responsibilities for many items/links in one request). The two-step lookup is unavoidable
// because ControlImplementationResponsibility and ProvidedControlImplementation are siblings
// under Export with no direct FK between them — only the shared OSCAL-level provided-uuid
// value — so responsibilities are scoped by (export_id, provided_uuid) pairs, not
// provided_uuid alone, since provided-uuid values are only unique within a single upstream's
// Export. providedUUIDs with no matching ProvidedControlImplementation row (e.g. the upstream
// row was since deleted) map to an empty slice, not an error or a missing key.
func bulkResolveUpstreamResponsibilities(db *gorm.DB, providedUUIDs []uuid.UUID) (map[uuid.UUID][]upstreamResponsibility, error) {
	result := make(map[uuid.UUID][]upstreamResponsibility, len(providedUUIDs))
	for _, id := range providedUUIDs {
		result[id] = []upstreamResponsibility{}
	}
	if len(providedUUIDs) == 0 {
		return result, nil
	}

	var provided []relational.ProvidedControlImplementation
	if err := db.Where("id IN ?", providedUUIDs).Find(&provided).Error; err != nil {
		return nil, err
	}
	if len(provided) == 0 {
		return result, nil
	}
	exportIDByProvided := make(map[uuid.UUID]uuid.UUID, len(provided))
	for _, p := range provided {
		exportIDByProvided[*p.ID] = p.ExportId
	}

	var responsibilities []relational.ControlImplementationResponsibility
	if err := db.Where("provided_uuid IN ?", providedUUIDs).Find(&responsibilities).Error; err != nil {
		return nil, err
	}
	for _, r := range responsibilities {
		// Scope by export_id too: provided-uuid values are only unique within a single
		// upstream's Export, so a bulk provided_uuid-only match could in principle pick
		// up a same-valued responsibility from an unrelated Export.
		if exportIDByProvided[r.ProvidedUuid] != r.ExportId {
			continue
		}
		result[r.ProvidedUuid] = append(result[r.ProvidedUuid], upstreamResponsibility{
			ResponsibilityUUID: *r.ID,
			Description:        r.Description,
		})
	}
	return result, nil
}

// uniqueUUIDs extracts the deduplicated set of UUIDs from items, preserving first-seen
// order — used to build IN-clause batches from a list of rows that may repeat the same
// referenced id (e.g. several leverage links pointing at the same offering).
func uniqueUUIDs[T any](items []T, extract func(T) uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(items))
	result := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		id := extract(item)
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result
}

// deriveSatisfaction is the single definition of "full iff every upstream
// responsibility has a matching downstream satisfied" (vacuously full when full is
// empty), shared by Subscribe (computing the satisfaction to store on a new leverage
// link) and LeveragedControls (recomputing it live rather than trusting the stored
// value). Returns the subset of full not covered by satisfiedUUIDs as outstanding.
func deriveSatisfaction(full []upstreamResponsibility, satisfiedUUIDs map[uuid.UUID]bool) (relational.SSPLeverageSatisfaction, []upstreamResponsibility) {
	outstanding := make([]upstreamResponsibility, 0)
	for _, r := range full {
		if !satisfiedUUIDs[r.ResponsibilityUUID] {
			outstanding = append(outstanding, r)
		}
	}
	if len(outstanding) == 0 {
		return relational.SSPLeverageSatisfactionFull, outstanding
	}
	return relational.SSPLeverageSatisfactionPartial, outstanding
}

// SSPLeverageHandler serves the downstream side of BCH-1338 Phase 2: subscribing to a
// published SSPExportOffering (recording OSCAL inherited + satisfied + a
// leveraged-authorization on the downstream SSP) and the read-only projection over what
// a downstream SSP has subscribed to.
type SSPLeverageHandler struct {
	sugar    *zap.SugaredLogger
	db       *gorm.DB
	pdp      authz.PDP
	failMode authz.FailMode
}

func NewSSPLeverageHandler(l *zap.SugaredLogger, db *gorm.DB, pdp authz.PDP, failMode authz.FailMode) *SSPLeverageHandler {
	return &SSPLeverageHandler{sugar: l, db: db, pdp: pdp, failMode: failMode}
}

// RegisterSubscribe mounts the subscribe route onto the same group the flat
// ssp-export-offering catalog uses, gated by ssp-export-offering:subscribe.
func (h *SSPLeverageHandler) RegisterSubscribe(g *echo.Group, guard middleware.ResourceGuard) {
	g.POST("/:id/subscribe", h.Subscribe, guard.Do(authz.ActionSubscribe))
}

// RegisterReAttest mounts the re-attestation route onto the SSP handler's own group,
// gated by the same ssp:update guard as any other write against the downstream SSP's own
// data — the SSP id is in the URL here (unlike Subscribe), so no bespoke
// authorizeDownstreamUpdate-style check is needed.
func (h *SSPLeverageHandler) RegisterReAttest(g *echo.Group, guard middleware.ResourceGuard) {
	g.POST("/:id/leveraged-controls/:linkId/attest", h.ReAttest, guard.Do(authz.ActionUpdate))
}

// RegisterProjection mounts the leveraged-controls projection onto the SSP handler's own
// route group, gated by the standard ssp:read.
func (h *SSPLeverageHandler) RegisterProjection(g *echo.Group, guard middleware.ResourceGuard) {
	g.GET("/:id/leveraged-controls", h.LeveragedControls, guard.Read())
}

// authorizeDownstreamUpdate enforces ssp:update on the downstream SSP identified by
// sspID, evaluated directly against the PDP rather than via route middleware — the
// downstream SSP id lives in the subscribe request body, not the URL, so the Subscribe
// route's own middleware (which only enforces ssp-export-offering:subscribe on the
// offering id in the URL) can't express this check. Mirrors PEP.Authorize's fail-mode
// handling. Critically, this is the only authorization check Subscribe performs against
// the downstream SSP's own resource — ssp:read on the *upstream* SSP is never evaluated
// anywhere in this path, which is the trust-boundary property AC #2 requires.
func (h *SSPLeverageHandler) authorizeDownstreamUpdate(ctx echo.Context, sspID uuid.UUID) (bool, error) {
	subject := middleware.SubjectFromContext(ctx)
	resource := authz.Resource{Type: authz.ResourceSSP, ID: sspID.String()}
	reqCtx := map[string]any{"method": ctx.Request().Method, "path": ctx.Path()}

	decision, err := h.pdp.Evaluate(ctx.Request().Context(), subject, authz.ActionUpdate, resource, reqCtx)
	if err != nil {
		if errors.Is(err, authz.ErrUnavailable) {
			h.sugar.Warnw("authz PDP unavailable for downstream ssp:update check",
				"sspId", sspID, "failMode", h.failMode, "error", err)
			return h.failMode == authz.FailOpen, nil
		}
		return false, err
	}
	return decision.Allow, nil
}

// isDownstreamAllowed reports whether downstreamSSPID may subscribe to offeringID
// (BCH-1342). A handler-level check, not a PDP/manifest-driven one — see this ticket's
// scoping decision (tasks.md) for why: BCH-1319's C1/C2 resource-attribute resolution
// isn't honoured by any shipped driver yet, so the offering's allow-list is enforced
// directly here, mirroring authorizeDownstreamUpdate's existing ad-hoc pattern. An
// offering with zero allow-list rows keeps the type-level default (any downstream
// permitted) for backwards compatibility.
func isDownstreamAllowed(db *gorm.DB, offeringID, downstreamSSPID uuid.UUID) (bool, error) {
	var total int64
	if err := db.Model(&relational.SSPExportOfferingAllowedDownstream{}).
		Where("offering_id = ?", offeringID).
		Count(&total).Error; err != nil {
		return false, fmt.Errorf("failed to count offering allow-list: %w", err)
	}
	if total == 0 {
		return true, nil
	}

	var matching int64
	if err := db.Model(&relational.SSPExportOfferingAllowedDownstream{}).
		Where("offering_id = ? AND downstream_ssp_id = ?", offeringID, downstreamSSPID).
		Count(&matching).Error; err != nil {
		return false, fmt.Errorf("failed to check offering allow-list membership: %w", err)
	}
	return matching > 0, nil
}

// findOrCreateThisSystemComponent finds the downstream's placeholder "this-system"
// component, creating one if none exists — not every SSP has one, and there's no
// guarantee the subscribing downstream does either.
func findOrCreateThisSystemComponent(tx *gorm.DB, systemImplementationID uuid.UUID) (*relational.SystemComponent, error) {
	var existing relational.SystemComponent
	err := tx.Where("system_implementation_id = ? AND type = ?", systemImplementationID, thisSystemComponentType).
		First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	created := relational.SystemComponent{
		Type:                   thisSystemComponentType,
		Title:                  "This System",
		Description:            "Placeholder component representing the system itself, used to anchor leveraged/inherited capabilities not tied to a specific local component.",
		SystemImplementationId: systemImplementationID,
	}
	if err := tx.Create(&created).Error; err != nil {
		return nil, err
	}
	return &created, nil
}

// findOrCreateImplementedRequirement finds the downstream's ImplementedRequirement for
// controlID under the given ControlImplementation, creating one if none exists. No
// find-or-create primitive exists elsewhere in the codebase for this — every existing
// creation path either does a naive insert (always creates) or a read-only lookup
// (404s if missing). The created flag distinguishes an insert from a match, so Subscribe
// can report which rows it actually materialized rather than making the caller re-walk the
// downstream SSP to find out.
func findOrCreateImplementedRequirement(tx *gorm.DB, controlImplementationID uuid.UUID, controlID string) (req *relational.ImplementedRequirement, created bool, err error) {
	var existing relational.ImplementedRequirement
	err = tx.Where("control_implementation_id = ? AND control_id = ?", controlImplementationID, controlID).
		First(&existing).Error
	if err == nil {
		return &existing, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}

	inserted := relational.ImplementedRequirement{
		ControlImplementationId: controlImplementationID,
		ControlId:               controlID,
	}
	if err := tx.Create(&inserted).Error; err != nil {
		return nil, false, err
	}
	return &inserted, true, nil
}

// findOrCreateStatement finds the ImplementedRequirement's child Statement for
// statementID, creating one if none exists.
func findOrCreateStatement(tx *gorm.DB, implementedRequirementID uuid.UUID, statementID string) (stmt *relational.Statement, created bool, err error) {
	var existing relational.Statement
	err = tx.Where("implemented_requirement_id = ? AND statement_id = ?", implementedRequirementID, statementID).
		First(&existing).Error
	if err == nil {
		return &existing, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}

	inserted := relational.Statement{
		ImplementedRequirementId: implementedRequirementID,
		StatementId:              statementID,
	}
	if err := tx.Create(&inserted).Error; err != nil {
		return nil, false, err
	}
	return &inserted, true, nil
}

// findOrCreateByComponent finds the ByComponent row for (parentID, parentType,
// componentUUID), creating one if none exists. parentType is "implemented_requirements"
// or "statements", matching the string constants used throughout system_security_plans.go
// — though Subscribe only ever passes "statements" now that the statement is the canonical
// anchor.
func findOrCreateByComponent(tx *gorm.DB, parentID uuid.UUID, parentType string, componentUUID uuid.UUID) (bc *relational.ByComponent, created bool, err error) {
	var existing relational.ByComponent
	err = tx.Where("parent_id = ? AND parent_type = ? AND component_uuid = ?", parentID, parentType, componentUUID).
		First(&existing).Error
	if err == nil {
		return &existing, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}

	inserted := relational.ByComponent{
		ParentID:      &parentID,
		ParentType:    &parentType,
		ComponentUUID: componentUUID,
	}
	if err := tx.Create(&inserted).Error; err != nil {
		return nil, false, err
	}
	return &inserted, true, nil
}

// subscribeCreatedRequirement / subscribeCreatedStatement / subscribeCreatedByComponent
// report one row Subscribe touched while materializing the downstream tree, with created
// distinguishing an insert from a reuse.
type subscribeCreatedRequirement struct {
	UUID      uuid.UUID `json:"uuid"`
	ControlID string    `json:"controlId"`
	Created   bool      `json:"created"`
}

type subscribeCreatedStatement struct {
	UUID                       uuid.UUID `json:"uuid"`
	StatementID                string    `json:"statementId"`
	ImplementedRequirementUUID uuid.UUID `json:"implementedRequirementUuid"`
	Created                    bool      `json:"created"`
}

type subscribeCreatedByComponent struct {
	UUID          uuid.UUID `json:"uuid"`
	StatementUUID uuid.UUID `json:"statementUuid"`
	ComponentUUID uuid.UUID `json:"componentUuid"`
	Created       bool      `json:"created"`
}

// subscribeCreated is the tree Subscribe materialized on the downstream, so the UI can
// render newly-created requirements straight from the subscribe response instead of
// re-walking the SSP.
type subscribeCreated struct {
	ImplementedRequirements []subscribeCreatedRequirement `json:"implementedRequirements"`
	Statements              []subscribeCreatedStatement   `json:"statements"`
	ByComponents            []subscribeCreatedByComponent `json:"byComponents"`
}

// subscribeMeta rides in GenericDataListResponse's existing Meta field rather than changing
// the response envelope: Data stays exactly the SSPLeverageLink[] every current caller
// already reads, and the created block is purely additive.
type subscribeMeta struct {
	Created subscribeCreated `json:"created"`
}

// subscribeCreationTracker accumulates the created-tree across a subscribe request's items,
// deduplicating by row id — several items can land on the same requirement or statement, and
// the first sighting is the one that knows whether it was inserted.
type subscribeCreationTracker struct {
	created     subscribeCreated
	seenReqs    map[uuid.UUID]bool
	seenStmts   map[uuid.UUID]bool
	seenByComps map[uuid.UUID]bool
}

func newSubscribeCreationTracker() *subscribeCreationTracker {
	return &subscribeCreationTracker{
		created: subscribeCreated{
			ImplementedRequirements: []subscribeCreatedRequirement{},
			Statements:              []subscribeCreatedStatement{},
			ByComponents:            []subscribeCreatedByComponent{},
		},
		seenReqs:    map[uuid.UUID]bool{},
		seenStmts:   map[uuid.UUID]bool{},
		seenByComps: map[uuid.UUID]bool{},
	}
}

func (t *subscribeCreationTracker) addRequirement(req *relational.ImplementedRequirement, created bool) {
	if t.seenReqs[*req.ID] {
		return
	}
	t.seenReqs[*req.ID] = true
	t.created.ImplementedRequirements = append(t.created.ImplementedRequirements, subscribeCreatedRequirement{
		UUID:      *req.ID,
		ControlID: req.ControlId,
		Created:   created,
	})
}

func (t *subscribeCreationTracker) addStatement(stmt *relational.Statement, created bool) {
	if t.seenStmts[*stmt.ID] {
		return
	}
	t.seenStmts[*stmt.ID] = true
	t.created.Statements = append(t.created.Statements, subscribeCreatedStatement{
		UUID:                       *stmt.ID,
		StatementID:                stmt.StatementId,
		ImplementedRequirementUUID: stmt.ImplementedRequirementId,
		Created:                    created,
	})
}

func (t *subscribeCreationTracker) addByComponent(bc *relational.ByComponent, statementUUID uuid.UUID, created bool) {
	if t.seenByComps[*bc.ID] {
		return
	}
	t.seenByComps[*bc.ID] = true
	t.created.ByComponents = append(t.created.ByComponents, subscribeCreatedByComponent{
		UUID:          *bc.ID,
		StatementUUID: statementUUID,
		ComponentUUID: bc.ComponentUUID,
		Created:       created,
	})
}

type subscribeLeveragedAuthorizationRequest struct {
	Title          string `json:"title"`
	PartyUUID      string `json:"partyUuid"`
	DateAuthorized string `json:"dateAuthorized,omitempty"`
}

type subscribeItemRequest struct {
	ItemID                       string   `json:"itemId"`
	SatisfiedResponsibilityUUIDs []string `json:"satisfiedResponsibilityUuids,omitempty"`
}

type subscribeRequest struct {
	DownstreamSSPID        string                                 `json:"downstreamSspId"`
	LeveragedAuthorization subscribeLeveragedAuthorizationRequest `json:"leveragedAuthorization"`
	Items                  []subscribeItemRequest                 `json:"items"`
}

func (r subscribeRequest) validate() error {
	if _, err := uuid.Parse(r.DownstreamSSPID); err != nil {
		return fmt.Errorf("downstreamSspId must be a valid UUID")
	}
	if r.LeveragedAuthorization.Title == "" {
		return fmt.Errorf("leveragedAuthorization.title is required")
	}
	if _, err := uuid.Parse(r.LeveragedAuthorization.PartyUUID); err != nil {
		return fmt.Errorf("leveragedAuthorization.partyUuid must be a valid UUID")
	}
	if len(r.Items) == 0 {
		return fmt.Errorf("items must not be empty")
	}
	for _, item := range r.Items {
		if _, err := uuid.Parse(item.ItemID); err != nil {
			return fmt.Errorf("items[].itemId must be a valid UUID")
		}
		for _, respID := range item.SatisfiedResponsibilityUUIDs {
			if _, err := uuid.Parse(respID); err != nil {
				return fmt.Errorf("items[].satisfiedResponsibilityUuids must be valid UUIDs")
			}
		}
	}
	return nil
}

// Subscribe godoc
//
//	@Summary		Subscribe to a published export offering
//	@Description	Records, on the downstream SSP named in the request body, an OSCAL
//	@Description	inherited-control-implementation and (optionally) satisfied-responsibility
//	@Description	entries per chosen offering item, plus one leveraged-authorization for the
//	@Description	whole request — all in a single atomic write. Never checks ssp:read on the
//	@Description	upstream SSP: the trust boundary is that subscribing to a published offering
//	@Description	only requires ssp-export-offering:subscribe on the offering and ssp:update on
//	@Description	the downstream SSP.
//	@Description
//	@Description	Every subscribed item must be statement-anchored: a legacy offering item with
//	@Description	no statement-id is rejected with 422. The materialized downstream tree is
//	@Description	always requirement -> statement -> by-component -> inherited + satisfied, and is
//	@Description	reported back in meta.created (each row flagged created:true when inserted,
//	@Description	false when an existing row was reused) so the caller can render newly-created
//	@Description	requirements without re-walking the SSP. The data payload is unchanged.
//	@Tags			SSP Export Offerings
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string				true	"Offering ID"
//	@Param			subscribe	body		subscribeRequest	true	"Subscribe request"
//	@Success		201			{object}	handler.GenericDataListResponse[relational.SSPLeverageLink]
//	@Failure		400			{object}	api.Error
//	@Failure		403			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		422			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/ssp-export-offerings/{id}/subscribe [post]
func (h *SSPLeverageHandler) Subscribe(ctx echo.Context) error {
	offeringIdParam := ctx.Param("id")
	offeringID, err := uuid.Parse(offeringIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid offering id", "id", offeringIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var offering relational.SSPExportOffering
	if err := h.db.Preload("Items").
		Where("status = ?", relational.SSPExportOfferingStatusPublished).
		First(&offering, "id = ?", offeringID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export offering not found")))
		}
		h.sugar.Errorf("Failed to load export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var req subscribeRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := req.validate(); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	downstreamSSPID := uuid.MustParse(req.DownstreamSSPID)

	allowed, err := h.authorizeDownstreamUpdate(ctx, downstreamSSPID)
	if err != nil {
		h.sugar.Errorf("authz evaluation failed for subscribe: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("authorization error")))
	}
	if !allowed {
		return echo.NewHTTPError(http.StatusForbidden, "forbidden")
	}

	itemsByID := make(map[uuid.UUID]relational.SSPExportOfferingItem, len(offering.Items))
	for _, item := range offering.Items {
		itemsByID[*item.ID] = item
	}
	seenProvidedUUIDs := make(map[uuid.UUID]bool, len(req.Items))
	for _, reqItem := range req.Items {
		item, ok := itemsByID[uuid.MustParse(reqItem.ItemID)]
		if !ok {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("unknown offering item id %q", reqItem.ItemID)))
		}
		// The statement is the canonical anchor: a legacy item with no statement-id cannot
		// be subscribed to, because there is no clause to attribute the inherited
		// responsibility against. Fail loudly rather than falling back to anchoring the
		// by-component at the requirement level — that fallback is what produced
		// requirement-anchored rows the API could never delete.
		if item.StatementID == nil || strings.TrimSpace(*item.StatementID) == "" {
			return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(fmt.Errorf(
				"offering item %q has no statement-id: shared responsibility is tracked per statement, so this legacy item must be re-curated against a statement before it can be subscribed to", reqItem.ItemID)))
		}
		// A request can't subscribe to the same provided-uuid twice in one call: besides
		// being nonsensical, it would otherwise slip past the existing-link pre-check
		// below (which only compares against already-committed rows) and hit the
		// UNIQUE(downstream_ssp_id, provided_uuid) constraint mid-transaction.
		if seenProvidedUUIDs[item.ProvidedUUID] {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("duplicate provided-uuid %q in request items", item.ProvidedUUID)))
		}
		seenProvidedUUIDs[item.ProvidedUUID] = true
	}

	var downstream relational.SystemSecurityPlan
	if err := h.db.
		Preload("ControlImplementation").
		Preload("SystemImplementation.Components").
		First(&downstream, "id = ?", downstreamSSPID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("downstream SSP not found")))
		}
		h.sugar.Errorf("Failed to load downstream SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	// SystemImplementation/ControlImplementation are has-one associations without their
	// own not-null guarantee at this layer: a SystemSecurityPlan row created outside the
	// normal OSCAL create/import cascade (or missing its child row for any other reason)
	// preloads them as zero-value structs with a nil ID, which would otherwise panic when
	// dereferenced below.
	if downstream.SystemImplementation.ID == nil || downstream.ControlImplementation.ID == nil {
		return ctx.JSON(http.StatusUnprocessableEntity,
			api.NewError(fmt.Errorf("downstream SSP is missing its system-implementation or control-implementation")))
	}

	// Pre-check (downstream_ssp_id, provided_uuid) uniqueness before opening the write
	// transaction, so the common case (a genuine duplicate subscribe) gets a clean 409
	// without the cost of a transaction. This can't catch a concurrent request racing the
	// same insert, though — that's caught inside the transaction below.
	for _, reqItem := range req.Items {
		item := itemsByID[uuid.MustParse(reqItem.ItemID)]
		err := h.db.Where("downstream_ssp_id = ? AND provided_uuid = ?", downstreamSSPID, item.ProvidedUUID).
			First(&relational.SSPLeverageLink{}).Error
		if err == nil {
			return ctx.JSON(http.StatusConflict, api.NewError(fmt.Errorf("already subscribed to provided-uuid %q", item.ProvidedUUID)))
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Errorf("Failed to check existing leverage link: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Resolve and validate every item's satisfied-responsibility selection before opening
	// the write transaction, so an unknown responsibility uuid — a client input error —
	// is a clean 400 rather than a mid-transaction rollback surfaced as a 500. The
	// resolved sets are reused inside the transaction below instead of re-querying.
	providedUUIDs := make([]uuid.UUID, 0, len(req.Items))
	for _, reqItem := range req.Items {
		providedUUIDs = append(providedUUIDs, itemsByID[uuid.MustParse(reqItem.ItemID)].ProvidedUUID)
	}
	fullSetByProvided, err := bulkResolveUpstreamResponsibilities(h.db, providedUUIDs)
	if err != nil {
		h.sugar.Errorf("Failed to resolve upstream responsibilities: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	for _, reqItem := range req.Items {
		item := itemsByID[uuid.MustParse(reqItem.ItemID)]
		fullByUUID := make(map[uuid.UUID]bool, len(fullSetByProvided[item.ProvidedUUID]))
		for _, r := range fullSetByProvided[item.ProvidedUUID] {
			fullByUUID[r.ResponsibilityUUID] = true
		}
		for _, respIDStr := range reqItem.SatisfiedResponsibilityUUIDs {
			if !fullByUUID[uuid.MustParse(respIDStr)] {
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
					"responsibility uuid %q is not a valid responsibility for provided-uuid %q", respIDStr, item.ProvidedUUID)))
			}
		}
	}

	dateAuthorized := time.Now()
	if req.LeveragedAuthorization.DateAuthorized != "" {
		parsed, err := time.Parse(time.RFC3339, req.LeveragedAuthorization.DateAuthorized)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("leveragedAuthorization.dateAuthorized must be RFC3339")))
		}
		dateAuthorized = parsed
	}
	attestedBy := actorUserID(ctx)
	now := time.Now()

	var links []relational.SSPLeverageLink
	tracker := newSubscribeCreationTracker()
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		// A retried transaction must not double-report rows from the abandoned attempt.
		tracker = newSubscribeCreationTracker()
		links = nil

		downstreamAllowed, err := isDownstreamAllowed(tx, offeringID, downstreamSSPID)
		if err != nil {
			return err
		}
		if !downstreamAllowed {
			return errDownstreamNotAllowed
		}

		thisSystemComponent, err := findOrCreateThisSystemComponent(tx, *downstream.SystemImplementation.ID)
		if err != nil {
			return err
		}

		leveragedAuth := relational.LeveragedAuthorization{
			Title:                  req.LeveragedAuthorization.Title,
			PartyUUID:              uuid.MustParse(req.LeveragedAuthorization.PartyUUID),
			DateAuthorized:         dateAuthorized,
			SystemImplementationId: *downstream.SystemImplementation.ID,
		}
		if err := tx.Create(&leveragedAuth).Error; err != nil {
			return err
		}

		for _, reqItem := range req.Items {
			item := itemsByID[uuid.MustParse(reqItem.ItemID)]

			implReq, reqCreated, err := findOrCreateImplementedRequirement(tx, *downstream.ControlImplementation.ID, item.ControlID)
			if err != nil {
				return err
			}
			tracker.addRequirement(implReq, reqCreated)

			// item.StatementID is guaranteed non-empty by the pre-transaction check above,
			// so the materialized tree is always requirement -> statement -> by-component.
			stmt, stmtCreated, err := findOrCreateStatement(tx, *implReq.ID, *item.StatementID)
			if err != nil {
				return err
			}
			tracker.addStatement(stmt, stmtCreated)

			byComponent, bcCreated, err := findOrCreateByComponent(tx, *stmt.ID, "statements", *thisSystemComponent.ID)
			if err != nil {
				return err
			}
			tracker.addByComponent(byComponent, *stmt.ID, bcCreated)

			inherited := relational.InheritedControlImplementation{
				ByComponentId: *byComponent.ID,
				ProvidedUuid:  item.ProvidedUUID,
				Description:   fmt.Sprintf("Inherited from offering %q (%s), v%d", offering.Title, offering.ID.String(), offering.Version),
			}
			if err := tx.Create(&inherited).Error; err != nil {
				return err
			}

			// Reuse the set resolved and validated before the transaction opened — every
			// uuid in reqItem.SatisfiedResponsibilityUUIDs is already confirmed to be a
			// member of it, so no further validation or DB lookup is needed here.
			fullSet := fullSetByProvided[item.ProvidedUUID]
			fullByUUID := make(map[uuid.UUID]upstreamResponsibility, len(fullSet))
			for _, r := range fullSet {
				fullByUUID[r.ResponsibilityUUID] = r
			}

			satisfiedSet := make(map[uuid.UUID]bool, len(reqItem.SatisfiedResponsibilityUUIDs))
			for _, respIDStr := range reqItem.SatisfiedResponsibilityUUIDs {
				respID := uuid.MustParse(respIDStr)
				if satisfiedSet[respID] {
					continue
				}
				satisfiedSet[respID] = true
				satisfied := relational.SatisfiedControlImplementationResponsibility{
					ByComponentId:      *byComponent.ID,
					ResponsibilityUuid: respID,
					Description:        fullByUUID[respID].Description,
				}
				if err := tx.Create(&satisfied).Error; err != nil {
					return err
				}
			}

			satisfaction, _ := deriveSatisfaction(fullSet, satisfiedSet)

			link := relational.SSPLeverageLink{
				DownstreamSSPID:   downstreamSSPID,
				UpstreamSSPID:     offering.SSPID,
				OfferingID:        *offering.ID,
				OfferingVersion:   offering.Version,
				ControlID:         item.ControlID,
				StatementID:       item.StatementID,
				ProvidedUUID:      item.ProvidedUUID,
				InheritedUUID:     *inherited.ID,
				LeveragedAuthUUID: *leveragedAuth.ID,
				Satisfaction:      satisfaction,
				Status:            relational.SSPLeverageStatusActive,
				AttestedAt:        &now,
				AttestedByID:      attestedBy,
			}
			if err := tx.Create(&link).Error; err != nil {
				if isUniqueViolation(err) {
					return errDuplicateLeverageLink
				}
				return err
			}
			links = append(links, link)
		}
		return nil
	}); err != nil {
		if errors.Is(err, errDuplicateLeverageLink) {
			return ctx.JSON(http.StatusConflict, api.NewError(err))
		}
		if errors.Is(err, errDownstreamNotAllowed) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}
		h.sugar.Errorf("Failed to subscribe to export offering: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataListResponse[relational.SSPLeverageLink]{
		Data: links,
		Meta: subscribeMeta{Created: tracker.created},
	})
}

type leveragedControlInheritedFrom struct {
	UpstreamSSPID   uuid.UUID `json:"upstreamSspId"`
	OfferingID      uuid.UUID `json:"offeringId"`
	OfferingTitle   string    `json:"offeringTitle"`
	OfferingVersion int       `json:"offeringVersion"`
}

type leveragedControlResponse struct {
	ID                          uuid.UUID                          `json:"id"`
	ControlID                   string                             `json:"controlId"`
	StatementID                 *string                            `json:"statementId,omitempty"`
	InheritedFrom               leveragedControlInheritedFrom      `json:"inheritedFrom"`
	Satisfaction                relational.SSPLeverageSatisfaction `json:"satisfaction"`
	Status                      relational.SSPLeverageStatus       `json:"status"`
	OutstandingResponsibilities []upstreamResponsibility           `json:"outstandingResponsibilities"`
	// ResponsibilityPosture is the live, evidence-backed posture (satisfied /
	// not-satisfied / unknown) per upstream responsibility uuid under this link's
	// provided-uuid — computed via filter_responsibilities (BCH-1339), independent of
	// Satisfaction/OutstandingResponsibilities above (which reflect what was attested at
	// subscribe time, not current evidence).
	ResponsibilityPosture map[uuid.UUID]string `json:"responsibilityPosture"`
	// DriftRiskID is the open drift risk for this link (BCH-1341's applyDriftToLink /
	// computeDedupeKeyForLeverageDrift convention), set only when Status is Drifted and a
	// matching risk is still open — nil otherwise (including for Revoked, which has no
	// re-attest path and thus no risk to link).
	DriftRiskID *uuid.UUID `json:"driftRiskId,omitempty"`
}

// LeveragedControls godoc
//
//	@Summary		Project a downstream SSP's leveraged controls
//	@Description	Read-only view over the downstream SSP's own inherited/satisfied entries
//	@Description	joined to ssp_leverage_links + the upstream offering. Per control/statement,
//	@Description	returns which offering it was inherited from, whether satisfaction is full
//	@Description	or partial (recomputed live from the current satisfied-responsibility rows,
//	@Description	not trusted from the link's stored value), any outstanding
//	@Description	responsibilities, and live evidence-backed posture per responsibility uuid
//	@Description	(satisfied/not-satisfied/unknown, via filter_responsibilities). Writes
//	@Description	nothing; never touches profile_controls/controls.
//	@Tags			SSP Export Offerings
//	@Produce		json
//	@Param			id	path		string	true	"Downstream SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[leveragedControlResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/leveraged-controls [get]
func (h *SSPLeverageHandler) LeveragedControls(ctx echo.Context) error {
	sspIdParam := ctx.Param("id")
	sspID, err := uuid.Parse(sspIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", sspIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.db.Select("id").First(&relational.SystemSecurityPlan{}, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorf("Failed to load SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	projection, err := projectLeveragedControls(h.db, sspID)
	if err != nil {
		h.sugar.Errorf("Failed to project leveraged controls: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	result := make([]leveragedControlResponse, 0, len(projection))
	for _, p := range projection {
		result = append(result, leveragedControlResponse{
			ID:          *p.Link.ID,
			ControlID:   p.Link.ControlID,
			StatementID: p.Link.StatementID,
			InheritedFrom: leveragedControlInheritedFrom{
				UpstreamSSPID:   p.Link.UpstreamSSPID,
				OfferingID:      p.Link.OfferingID,
				OfferingTitle:   p.OfferingTitle,
				OfferingVersion: p.Link.OfferingVersion,
			},
			Satisfaction:                p.Satisfaction,
			Status:                      p.Link.Status,
			OutstandingResponsibilities: p.Outstanding,
			ResponsibilityPosture:       p.Posture,
			DriftRiskID:                 p.DriftRiskID,
		})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[leveragedControlResponse]{Data: result})
}

// leveragedControlProjection is one downstream leverage link with everything the read
// models need already resolved: the live-recomputed satisfaction (never the link's cached
// value), the outstanding responsibilities, the evidence-backed posture, the open drift
// risk, the offering title, and the by-component + inherited row the link hangs off.
//
// Both the /leveraged-controls endpoint and the shared-responsibility rollup read this, so
// satisfaction is derived in exactly one place and neither surface can drift from the other.
type leveragedControlProjection struct {
	Link          relational.SSPLeverageLink
	OfferingTitle string
	ByComponentID uuid.UUID
	// Inherited is the downstream's own InheritedControlImplementation row this link
	// created; nil only if it has since been deleted out from under the link.
	Inherited    *relational.InheritedControlImplementation
	Satisfaction relational.SSPLeverageSatisfaction
	Outstanding  []upstreamResponsibility
	Posture      map[uuid.UUID]string
	DriftRiskID  *uuid.UUID
}

// projectLeveragedControls builds the projection for every leverage link on one downstream
// SSP in a fixed number of queries (six), independent of link count — the batching that
// replaced this code's original four-queries-per-link loop, preserved here so neither caller
// can regress it into an N+1.
func projectLeveragedControls(db *gorm.DB, sspID uuid.UUID) ([]leveragedControlProjection, error) {
	var links []relational.SSPLeverageLink
	if err := db.Where("downstream_ssp_id = ?", sspID).Order("id ASC").Find(&links).Error; err != nil {
		return nil, fmt.Errorf("failed to list leverage links: %w", err)
	}
	if len(links) == 0 {
		return []leveragedControlProjection{}, nil
	}

	offeringIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.OfferingID })
	var offerings []relational.SSPExportOffering
	if err := db.Select("id, title").Where("id IN ?", offeringIDs).Find(&offerings).Error; err != nil {
		return nil, fmt.Errorf("failed to load offerings for leverage links: %w", err)
	}
	offeringTitleByID := make(map[uuid.UUID]string, len(offerings))
	for _, o := range offerings {
		offeringTitleByID[*o.ID] = o.Title
	}

	inheritedIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.InheritedUUID })
	var inheritedRows []relational.InheritedControlImplementation
	if err := db.Where("id IN ?", inheritedIDs).Find(&inheritedRows).Error; err != nil {
		return nil, fmt.Errorf("failed to load inherited control implementations for leverage links: %w", err)
	}
	inheritedByID := make(map[uuid.UUID]relational.InheritedControlImplementation, len(inheritedRows))
	for _, i := range inheritedRows {
		inheritedByID[*i.ID] = i
	}

	providedUUIDs := uniqueUUIDs(links, func(l relational.SSPLeverageLink) uuid.UUID { return l.ProvidedUUID })
	fullSetByProvided, err := bulkResolveUpstreamResponsibilities(db, providedUUIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve upstream responsibilities for leverage links: %w", err)
	}

	byComponentIDs := uniqueUUIDs(inheritedRows, func(i relational.InheritedControlImplementation) uuid.UUID { return i.ByComponentId })
	var satisfiedRows []relational.SatisfiedControlImplementationResponsibility
	if len(byComponentIDs) > 0 {
		if err := db.Where("by_component_id IN ?", byComponentIDs).Find(&satisfiedRows).Error; err != nil {
			return nil, fmt.Errorf("failed to load satisfied responsibilities for leverage links: %w", err)
		}
	}
	satisfiedByComponent := make(map[uuid.UUID]map[uuid.UUID]bool, len(byComponentIDs))
	for _, s := range satisfiedRows {
		if satisfiedByComponent[s.ByComponentId] == nil {
			satisfiedByComponent[s.ByComponentId] = make(map[uuid.UUID]bool)
		}
		satisfiedByComponent[s.ByComponentId][s.ResponsibilityUuid] = true
	}

	// Batch every responsibility uuid under every link's provided-uuid into a single
	// ResponsibilityPosture call, rather than one call per link.
	var allResponsibilityUUIDs []uuid.UUID
	for _, full := range fullSetByProvided {
		for _, r := range full {
			allResponsibilityUUIDs = append(allResponsibilityUUIDs, r.ResponsibilityUUID)
		}
	}
	posture, err := ResponsibilityPosture(db, sspID, allResponsibilityUUIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute responsibility posture for leverage links: %w", err)
	}

	// Batch-resolve every drifted link's open drift risk in one query, keyed by the
	// dedupe_key convention computeDedupeKeyForLeverageDrift/applyDriftToLink already use —
	// rather than a lookup per drifted link.
	dedupeKeyToLinkID := make(map[string]uuid.UUID)
	dedupeKeys := make([]string, 0, len(links))
	for _, link := range links {
		if link.Status != relational.SSPLeverageStatusDrifted {
			continue
		}
		key := computeDedupeKeyForLeverageDrift(*link.ID)
		dedupeKeyToLinkID[key] = *link.ID
		dedupeKeys = append(dedupeKeys, key)
	}
	driftRiskIDByLinkID := make(map[uuid.UUID]uuid.UUID, len(dedupeKeys))
	if len(dedupeKeys) > 0 {
		var driftRisks []risks.Risk
		if err := db.Select("id, dedupe_key").
			Where("ssp_id = ? AND dedupe_key IN ? AND status != ?", sspID, dedupeKeys, risks.RiskStatusClosed).
			Find(&driftRisks).Error; err != nil {
			return nil, fmt.Errorf("failed to load drift risks for leverage links: %w", err)
		}
		for _, r := range driftRisks {
			if linkID, ok := dedupeKeyToLinkID[r.DedupeKey]; ok {
				driftRiskIDByLinkID[linkID] = *r.ID
			}
		}
	}

	result := make([]leveragedControlProjection, 0, len(links))
	for _, link := range links {
		var inherited *relational.InheritedControlImplementation
		var byComponentID uuid.UUID
		if row, ok := inheritedByID[link.InheritedUUID]; ok {
			inherited = &row
			byComponentID = row.ByComponentId
		}

		full := fullSetByProvided[link.ProvidedUUID]
		satisfaction, outstanding := deriveSatisfaction(full, satisfiedByComponent[byComponentID])

		linkPosture := make(map[uuid.UUID]string, len(full))
		for _, r := range full {
			linkPosture[r.ResponsibilityUUID] = posture[r.ResponsibilityUUID]
		}

		var driftRiskID *uuid.UUID
		if id, ok := driftRiskIDByLinkID[*link.ID]; ok {
			driftRiskID = &id
		}

		result = append(result, leveragedControlProjection{
			Link:          link,
			OfferingTitle: offeringTitleByID[link.OfferingID],
			ByComponentID: byComponentID,
			Inherited:     inherited,
			Satisfaction:  satisfaction,
			Outstanding:   outstanding,
			Posture:       linkPosture,
			DriftRiskID:   driftRiskID,
		})
	}

	return result, nil
}

// ReAttest clears drift on a leverage link (BCH-1341): bumps OfferingVersion to the
// offering's current Version, refreshes Satisfaction against the current upstream
// responsibility set and downstream satisfied set, flips the link back to active, and
// marks the associated drift risk remediated — all in one transaction. Human-in-the-loop
// only: this is the sole path that clears drift, there is no automatic re-activation.
func (h *SSPLeverageHandler) ReAttest(ctx echo.Context) error {
	sspIdParam := ctx.Param("id")
	sspID, err := uuid.Parse(sspIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", sspIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	linkIdParam := ctx.Param("linkId")
	linkID, err := uuid.Parse(linkIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid leverage link id", "linkId", linkIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var link relational.SSPLeverageLink
	if err := h.db.First(&link, "id = ?", linkID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("leverage link not found")))
		}
		h.sugar.Errorf("Failed to load leverage link: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if link.DownstreamSSPID != sspID {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("leverage link not found")))
	}
	if link.Status != relational.SSPLeverageStatusDrifted {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("leverage link is not drifted")))
	}

	attestedBy := actorUserID(ctx)
	now := time.Now()

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var offering relational.SSPExportOffering
		if err := tx.First(&offering, "id = ?", link.OfferingID).Error; err != nil {
			return fmt.Errorf("failed to load offering: %w", err)
		}

		var inherited relational.InheritedControlImplementation
		if err := tx.First(&inherited, "id = ?", link.InheritedUUID).Error; err != nil {
			return fmt.Errorf("failed to load inherited control implementation: %w", err)
		}

		var satisfiedRows []relational.SatisfiedControlImplementationResponsibility
		if err := tx.Where("by_component_id = ?", inherited.ByComponentId).Find(&satisfiedRows).Error; err != nil {
			return fmt.Errorf("failed to load satisfied responsibilities: %w", err)
		}
		satisfiedUUIDs := make(map[uuid.UUID]bool, len(satisfiedRows))
		for _, s := range satisfiedRows {
			satisfiedUUIDs[s.ResponsibilityUuid] = true
		}

		fullSet, err := resolveUpstreamResponsibilities(tx, link.ProvidedUUID)
		if err != nil {
			return fmt.Errorf("failed to resolve upstream responsibilities: %w", err)
		}
		satisfaction, _ := deriveSatisfaction(fullSet, satisfiedUUIDs)

		// Require the link to still be Drifted at update time, not just at the pre-check
		// read above — otherwise a concurrent re-attest, or a fresh drift trigger landing
		// in between, would be silently overwritten by this stale request.
		result := tx.Model(&relational.SSPLeverageLink{}).
			Where("id = ? AND status = ?", link.ID, relational.SSPLeverageStatusDrifted).
			Updates(map[string]any{
				"offering_version": offering.Version,
				"status":           relational.SSPLeverageStatusActive,
				"satisfaction":     satisfaction,
				"attested_at":      &now,
				"attested_by_id":   attestedBy,
			})
		if result.Error != nil {
			return fmt.Errorf("failed to update leverage link: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return errLeverageLinkNoLongerDrifted
		}

		dedupeKey := computeDedupeKeyForLeverageDrift(*link.ID)
		var driftRisk risks.Risk
		err = tx.Where("dedupe_key = ? AND status != ?", dedupeKey, risks.RiskStatusClosed).First(&driftRisk).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("failed to load drift risk: %w", err)
		}

		oldStatus := driftRisk.Status
		driftRisk.Status = string(risks.RiskStatusRemediated)
		if err := tx.Save(&driftRisk).Error; err != nil {
			return fmt.Errorf("failed to remediate drift risk: %w", err)
		}
		if err := emitLeverageDriftRiskEvent(tx, *driftRisk.ID, string(risks.RiskEventTypeStatusChange), map[string]interface{}{
			"from":             oldStatus,
			"to":               string(risks.RiskStatusRemediated),
			"reason":           "re-attested",
			"leverage_link_id": link.ID,
		}, now); err != nil {
			return err
		}
		return risks.NewRiskService(tx).RecordRiskScoreSnapshot(tx, *driftRisk.ID, risks.RiskEventTypeStatusChange, attestedBy, now)
	}); err != nil {
		if errors.Is(err, errLeverageLinkNoLongerDrifted) {
			return ctx.JSON(http.StatusConflict, api.NewError(err))
		}
		h.sugar.Errorf("Failed to re-attest leverage link: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var updated relational.SSPLeverageLink
	if err := h.db.First(&updated, "id = ?", link.ID).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[relational.SSPLeverageLink]{Data: updated})
}
