package oscal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	"github.com/google/uuid"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SSPJobEnqueuer is a minimal interface for enqueueing SSP-related background jobs.
// Defined here to avoid a circular import between the oscal handler and worker packages.
type SSPJobEnqueuer interface {
	EnqueueOrphanedRiskCleanup(ctx context.Context, sspID uuid.UUID, oldProfileID, newProfileID *uuid.UUID) error
	EnqueueDashboardSuggestionCells(ctx context.Context, runID uuid.UUID, cellCount int) error
	EnqueueLeverageDriftNotification(ctx context.Context, riskID, linkID uuid.UUID, reason string) error
}

// profileSummary is a lightweight DTO returned by the multi-profile list endpoint.
type profileSummary struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
}

// addProfileRequest is the request body for the AddProfile endpoint.
type addProfileRequest struct {
	ProfileID string `json:"profileId"`
}

// normalizeControlID lowercases a control ID. It is used only to derive a
// case-insensitive comparison key (dedup, map lookups, SQL IN lists). The
// lowercased value must NOT be persisted as an ImplementedRequirement.ControlId
// or returned for display — storage and display use the catalog-canonical
// casing (e.g. "GD.Sec.C08"). See dedupeControlIDs for the value-preserving
// counterpart.
func normalizeControlID(controlID string) string {
	return strings.ToLower(controlID)
}

// normalizeControlIDs lowercases and case-insensitively dedupes a slice of
// control IDs. Use it to build comparison keys / SQL IN lists, never to produce
// values that get stored or shown to users.
func normalizeControlIDs(controlIDs []string) []string {
	seen := make(map[string]struct{}, len(controlIDs))
	normalized := make([]string, 0, len(controlIDs))
	for _, controlID := range controlIDs {
		canonicalID := normalizeControlID(controlID)
		if _, exists := seen[canonicalID]; exists {
			continue
		}
		seen[canonicalID] = struct{}{}
		normalized = append(normalized, canonicalID)
	}
	return normalized
}

// dedupeControlIDs removes duplicates case-insensitively while PRESERVING the
// original (catalog-canonical) casing of the first occurrence. This is the
// resolver-side counterpart to normalizeControlIDs: control IDs flow through
// here so that the canonical casing reaches storage and display, while matching
// elsewhere stays case-insensitive via normalizeControlID keys.
func dedupeControlIDs(controlIDs []string) []string {
	seen := make(map[string]struct{}, len(controlIDs))
	deduped := make([]string, 0, len(controlIDs))
	for _, controlID := range controlIDs {
		key := normalizeControlID(controlID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, controlID)
	}
	return deduped
}

func buildProfileSummaries(profiles []relational.Profile) ([]profileSummary, error) {
	summaries := make([]profileSummary, 0, len(profiles))
	for _, p := range profiles {
		if p.ID == nil {
			return nil, errors.New("profile is missing ID")
		}

		ps := profileSummary{ID: p.ID.String()}
		if p.Metadata.Title != "" {
			ps.Title = p.Metadata.Title
		}
		summaries = append(summaries, ps)
	}
	return summaries, nil
}

type SystemSecurityPlanHandler struct {
	sugar             *zap.SugaredLogger
	db                *gorm.DB
	suggestionService *relational.SystemComponentSuggestionService
	jobEnqueuer       SSPJobEnqueuer
}

// profileControlCache memoizes the set of resolved control IDs for a profile.
//
// It is a process-wide singleton (profileControlsCache) rather than per-handler
// state on purpose: profile control resolution is a pure function of persisted
// data, and the cache must stay coherent across every handler that reads or
// mutates profiles (the SSP handler reads it, while the profile/import handlers
// change a profile's controls). Writes go through store, which never caches an
// empty set — a profile resolves to zero controls transiently while its imports
// are being configured, and caching that would poison the entry for the process
// lifetime. Invalidation is centralized in SyncProfileControls, the single
// chokepoint that rewrites a profile's resolved controls in the profile_controls
// pivot table.
type profileControlCache struct {
	entries sync.Map // map[uuid.UUID][]string
}

var profileControlsCache = &profileControlCache{}

// load returns the cached control IDs for a profile, if present and well-typed.
// A malformed entry (only possible via test seams) is dropped and reported as a
// miss.
func (c *profileControlCache) load(profileID uuid.UUID) ([]string, bool) {
	val, ok := c.entries.Load(profileID)
	if !ok {
		return nil, false
	}
	controlIDs, ok := val.([]string)
	if !ok {
		c.entries.Delete(profileID)
		return nil, false
	}
	return controlIDs, true
}

// store caches the resolved control IDs for a profile. Empty results are never
// cached — see the type doc.
func (c *profileControlCache) store(profileID uuid.UUID, controlIDs []string) {
	if len(controlIDs) == 0 {
		return
	}
	c.entries.Store(profileID, controlIDs)
}

// invalidate drops any cached entry for a profile so the next read repopulates
// from the profile_controls pivot table. Safe to call even when no entry exists.
func (c *profileControlCache) invalidate(profileID uuid.UUID) {
	c.entries.Delete(profileID)
}

type SystemComponentRequest struct {
	oscalTypes_1_1_3.SystemComponent
	DefinedComponentID *uuid.UUID `json:"definedComponentId,omitempty"`
}

type ApplySuggestionRequest struct {
	ComponentDefinitionID *uuid.UUID `json:"component-definition-id" binding:"required" format:"uuid"`
	DefinedComponentID    *uuid.UUID `json:"defined-component-id" binding:"required" format:"uuid"`
}

func (r *ApplySuggestionRequest) Validate() error {
	if r.ComponentDefinitionID == nil || *r.ComponentDefinitionID == uuid.Nil {
		return fmt.Errorf("component-definition-id is required")
	}
	if r.DefinedComponentID == nil || *r.DefinedComponentID == uuid.Nil {
		return fmt.Errorf("defined-component-id is required")
	}
	return nil
}

func NewSystemSecurityPlanHandler(sugar *zap.SugaredLogger, db *gorm.DB, evidenceSvc *evidencesvc.EvidenceService, jobEnqueuer SSPJobEnqueuer) *SystemSecurityPlanHandler {
	return &SystemSecurityPlanHandler{
		sugar:             sugar,
		db:                db,
		suggestionService: relational.NewSystemComponentSuggestionService(db, evidenceSvc),
		jobEnqueuer:       jobEnqueuer,
	}
}

// getControlIDsForProfile returns all control IDs for a given profile, using an optimized multi-step resolution path:
// 1. In-memory cache
// 2. ProfileControl pivot table in the database
// 3. Fallback to full recursive resolution (and updates the cache/pivot table)
func (h *SystemSecurityPlanHandler) getControlIDsForProfile(profileID uuid.UUID) ([]string, error) {
	// 1. Check in-memory cache first
	if cachedControlIDs, ok := profileControlsCache.load(profileID); ok {
		dedupedControlIDs := dedupeControlIDs(cachedControlIDs)
		profileControlsCache.store(profileID, dedupedControlIDs)
		return dedupedControlIDs, nil
	}

	// 2. Check the ProfileControl pivot table in DB
	var controlIDs []string
	if err := h.db.Table("profile_controls").
		Distinct("control_id").
		Where("profile_id = ?", profileID).
		Pluck("control_id", &controlIDs).Error; err != nil {
		h.sugar.Warnw("Failed to fetch control IDs from pivot table", "profileId", profileID, "error", err)
	}

	// 3. Fallback to full resolution if pivot table is empty or failed
	if len(controlIDs) == 0 {
		profile, err := FindFullProfile(h.db, profileID)
		if err != nil {
			return nil, err
		}
		if profile.ID == nil {
			return nil, errors.New("profile ID is nil")
		}
		controlIDs, err = h.extractControlIDsFromProfile(profile)
		if err != nil {
			return nil, err
		}
	}

	controlIDs = dedupeControlIDs(controlIDs)
	// store skips empty results (see profileControlCache): a profile resolves to
	// zero controls transiently while its imports are being configured, and that
	// empty state must not be cached.
	profileControlsCache.store(profileID, controlIDs)
	return controlIDs, nil
}

// getControlIDsForAllProfiles resolves control IDs from all profiles bound to an SSP
// via the M:M relationship. Returns deduplicated control IDs across all profiles.
// It first attempts a single batch query against the profile_controls pivot table,
// then falls back to per-profile resolution for any profile missing pivot rows.
func (h *SystemSecurityPlanHandler) getControlIDsForAllProfiles(profiles []relational.Profile) ([]string, error) {
	if len(profiles) == 0 {
		return nil, nil
	}

	profileIDs := make([]uuid.UUID, 0, len(profiles))
	for _, p := range profiles {
		if p.ID != nil {
			profileIDs = append(profileIDs, *p.ID)
		}
	}
	if len(profileIDs) == 0 {
		return nil, nil
	}

	seenControls := make(map[string]struct{})
	seenProfiles := make(map[uuid.UUID]struct{})
	allControlIDs := make([]string, 0)
	appendControlIDs := func(controlIDs []string) {
		for _, cid := range controlIDs {
			// Dedupe case-insensitively but keep the canonical casing of the value.
			key := normalizeControlID(cid)
			if _, exists := seenControls[key]; exists {
				continue
			}
			seenControls[key] = struct{}{}
			allControlIDs = append(allControlIDs, cid)
		}
	}

	type profileControlRow struct {
		ProfileID uuid.UUID `gorm:"column:profile_id"`
		ControlID string    `gorm:"column:control_id"`
	}

	var rows []profileControlRow
	batchErr := h.db.Table("profile_controls").
		Select("DISTINCT profile_id, control_id").
		Where("profile_id IN ?", profileIDs).
		Find(&rows).Error
	if batchErr != nil {
		h.sugar.Warnw("Batch query for profile controls failed, falling back to per-profile resolution", "error", batchErr)
	} else {
		for _, row := range rows {
			seenProfiles[row.ProfileID] = struct{}{}
			appendControlIDs([]string{row.ControlID})
		}
	}

	// Fallback: per-profile resolution handles OSCAL parsing when the pivot
	// table has not been populated yet for one or more bound profiles.
	for _, pid := range profileIDs {
		if batchErr == nil {
			if _, exists := seenProfiles[pid]; exists {
				continue
			}
		}
		controlIDs, err := h.getControlIDsForProfile(pid)
		if err != nil {
			return nil, fmt.Errorf("resolve controls for profile %s: %w", pid, err)
		}
		appendControlIDs(controlIDs)
	}

	return allControlIDs, nil
}

// canonicalizeControlID resolves controlID to its catalog-canonical casing
// (e.g. "gd.sec.c08" -> "GD.Sec.C08") by matching it case-insensitively against
// the controls of the profiles bound to the SSP via the profile_controls pivot.
// If no bound profile contains the control (e.g. an ad-hoc requirement created
// directly, or before profiles are resolved), the input is returned unchanged
// so direct creation still works. This keeps control IDs stored on
// ImplementedRequirements consistent with the catalog regardless of the casing
// the client supplied.
func (h *SystemSecurityPlanHandler) canonicalizeControlID(sspID uuid.UUID, controlID string) string {
	if controlID == "" {
		return controlID
	}
	var matches []string
	if err := h.db.Table("profile_controls").
		Joins("JOIN ssp_profiles ON ssp_profiles.profile_id = profile_controls.profile_id").
		Where("ssp_profiles.system_security_plan_id = ? AND UPPER(profile_controls.control_id) = UPPER(?)", sspID, controlID).
		Limit(1).
		Pluck("profile_controls.control_id", &matches).Error; err != nil {
		h.sugar.Warnw("Failed to canonicalize control ID; storing as provided",
			"sspId", sspID, "controlId", controlID, "error", err)
		return controlID
	}
	if len(matches) == 0 || matches[0] == "" {
		return controlID
	}
	return matches[0]
}

// validateSSPInput validates SSP input following OSCAL requirements
func (h *SystemSecurityPlanHandler) validateSSPInput(ssp *oscalTypes_1_1_3.SystemSecurityPlan) error {
	if ssp.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(ssp.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if ssp.Metadata.Title == "" {
		return fmt.Errorf("metadata.title is required")
	}
	if ssp.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	return nil
}

// validateSystemUserInput validates system user input
func (h *SystemSecurityPlanHandler) validateSystemUserInput(user *oscalTypes_1_1_3.SystemUser) error {
	if user.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(user.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if user.Title == "" {
		return fmt.Errorf("title is required")
	}
	return nil
}

// validateSystemComponentInput validates system component input
func (h *SystemSecurityPlanHandler) validateSystemComponentInput(comp *oscalTypes_1_1_3.SystemComponent) error {
	if comp.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(comp.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if comp.Title == "" {
		return fmt.Errorf("title is required")
	}
	if comp.Type == "" {
		return fmt.Errorf("type is required")
	}
	return nil
}

// validateInventoryItemInput validates inventory item input
func (h *SystemSecurityPlanHandler) validateInventoryItemInput(item *oscalTypes_1_1_3.InventoryItem) error {
	if item.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(item.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	return nil
}

// validateImplementedRequirementInput validates implemented requirement input
func (h *SystemSecurityPlanHandler) validateImplementedRequirementInput(req *oscalTypes_1_1_3.ImplementedRequirement) error {
	if req.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(req.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if req.ControlId == "" {
		return fmt.Errorf("control-id is required")
	}
	return nil
}

func (h *SystemSecurityPlanHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("", h.List, guard.Read())
	api.POST("", h.Create, guard.Create())
	api.GET("/:id", h.Get, guard.Read())
	api.PUT("/:id", h.Update, guard.Update())
	api.GET("/:id/profile", h.GetProfile, guard.Read())
	api.PUT("/:id/profile", h.AttachProfile, guard.Update())
	api.GET("/:id/profiles", h.ListProfiles, guard.Read())
	api.POST("/:id/profiles", h.AddProfile, guard.Create())
	api.DELETE("/:id/profiles/:profileId", h.RemoveProfile, guard.Delete())
	api.DELETE("/:id", h.Delete, guard.Delete())
	api.GET("/:id/full", h.Full, guard.Read())
	api.GET("/:id/metadata", h.GetMetadata, guard.Read())
	api.PUT("/:id/metadata", h.UpdateMetadata, guard.Update())
	api.GET("/:id/import-profile", h.GetImportProfile, guard.Read())
	api.PUT("/:id/import-profile", h.UpdateImportProfile, guard.Update())
	api.GET("/:id/system-characteristics", h.GetCharacteristics, guard.Read())
	api.PUT("/:id/system-characteristics", h.UpdateCharacteristics, guard.Update())
	api.GET("/:id/system-characteristics/network-architecture", h.GetCharacteristicsNetworkArchitecture, guard.Read())
	api.POST("/:id/system-characteristics/network-architecture/diagrams", h.CreateCharacteristicsNetworkArchitectureDiagram, guard.Create())
	api.PUT("/:id/system-characteristics/network-architecture/diagrams/:diagram", h.UpdateCharacteristicsNetworkArchitectureDiagram, guard.Update())
	api.DELETE("/:id/system-characteristics/network-architecture/diagrams/:diagram", h.DeleteCharacteristicsNetworkArchitectureDiagram, guard.Delete())
	api.GET("/:id/system-characteristics/data-flow", h.GetCharacteristicsDataFlow, guard.Read())
	api.POST("/:id/system-characteristics/data-flow/diagrams", h.CreateCharacteristicsDataFlowDiagram, guard.Create())
	api.PUT("/:id/system-characteristics/data-flow/diagrams/:diagram", h.UpdateCharacteristicsDataFlowDiagram, guard.Update())
	api.DELETE("/:id/system-characteristics/data-flow/diagrams/:diagram", h.DeleteCharacteristicsDataFlowDiagram, guard.Delete())
	api.GET("/:id/system-characteristics/authorization-boundary", h.GetCharacteristicsAuthorizationBoundary, guard.Read())
	api.POST("/:id/system-characteristics/authorization-boundary/diagrams", h.CreateCharacteristicsAuthorizationBoundaryDiagram, guard.Create())
	api.PUT("/:id/system-characteristics/authorization-boundary/diagrams/:diagram", h.UpdateCharacteristicsAuthorizationBoundaryDiagram, guard.Update())
	api.DELETE("/:id/system-characteristics/authorization-boundary/diagrams/:diagram", h.DeleteCharacteristicsAuthorizationBoundaryDiagram, guard.Delete())
	api.GET("/:id/system-implementation", h.GetSystemImplementation, guard.Read())
	api.PUT("/:id/system-implementation", h.UpdateSystemImplementation, guard.Update())
	api.GET("/:id/system-implementation/users", h.GetSystemImplementationUsers, guard.Read())
	api.POST("/:id/system-implementation/users", h.CreateSystemImplementationUser, guard.Create())
	api.PUT("/:id/system-implementation/users/:userId", h.UpdateSystemImplementationUser, guard.Update())
	api.DELETE("/:id/system-implementation/users/:userId", h.DeleteSystemImplementationUser, guard.Delete())
	api.GET("/:id/system-implementation/components", h.GetSystemImplementationComponents, guard.Read())
	api.GET("/:id/system-implementation/components/:componentId", h.GetSystemImplementationComponent, guard.Read())
	api.POST("/:id/system-implementation/components", h.CreateSystemImplementationComponent, guard.Create())
	api.PUT("/:id/system-implementation/components/:componentId", h.UpdateSystemImplementationComponent, guard.Update())
	api.DELETE("/:id/system-implementation/components/:componentId", h.DeleteSystemImplementationComponent, guard.Delete())
	api.GET("/:id/system-implementation/inventory-items", h.GetSystemImplementationInventoryItems, guard.Read())
	api.POST("/:id/system-implementation/inventory-items", h.CreateSystemImplementationInventoryItem, guard.Create())
	api.PUT("/:id/system-implementation/inventory-items/:itemId", h.UpdateSystemImplementationInventoryItem, guard.Update())
	api.DELETE("/:id/system-implementation/inventory-items/:itemId", h.DeleteSystemImplementationInventoryItem, guard.Delete())
	api.GET("/:id/system-implementation/leveraged-authorizations", h.GetSystemImplementationLeveragedAuthorizations, guard.Read())
	api.POST("/:id/system-implementation/leveraged-authorizations", h.CreateSystemImplementationLeveragedAuthorization, guard.Create())
	api.PUT("/:id/system-implementation/leveraged-authorizations/:authId", h.UpdateSystemImplementationLeveragedAuthorization, guard.Update())
	api.DELETE("/:id/system-implementation/leveraged-authorizations/:authId", h.DeleteSystemImplementationLeveragedAuthorization, guard.Delete())
	api.GET("/:id/control-implementation", h.GetControlImplementation, guard.Read())
	api.PUT("/:id/control-implementation", h.UpdateControlImplementation, guard.Update())
	api.GET("/:id/control-implementation/implemented-requirements", h.GetImplementedRequirements, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements", h.CreateImplementedRequirement, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId", h.UpdateImplementedRequirement, guard.Update())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements", h.CreateImplementedRequirementStatement, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId", h.UpdateImplementedRequirementStatement, guard.Update())
	// Requirement-level by-component routes are legacy: the statement is the canonical
	// anchor for anything carrying shared responsibility, so there is deliberately no
	// requirement-level POST. Read, update and delete stay so existing requirement-anchored
	// rows can be wound down.
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId", h.GetImplementedRequirementByComponent, guard.Read())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId", h.UpdateImplementedRequirementByComponent, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId", h.DeleteImplementedRequirementByComponent, guard.Delete())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components", h.GetImplementedRequirementStatementByComponents, guard.Read())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId", h.GetImplementedRequirementStatementByComponent, guard.Read())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId", h.UpdateImplementedRequirementStatementByComponent, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId", h.DeleteImplementedRequirementStatementByComponent, guard.Delete())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components", h.CreateImplementedRequirementStatementByComponent, guard.Create())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export", h.GetImplementedRequirementByComponentExport, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export", h.CreateImplementedRequirementByComponentExport, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export", h.UpdateImplementedRequirementByComponentExport, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export", h.DeleteImplementedRequirementByComponentExport, guard.Delete())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/provided", h.GetImplementedRequirementByComponentExportProvided, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/provided", h.CreateImplementedRequirementByComponentExportProvided, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/provided/:providedId", h.UpdateImplementedRequirementByComponentExportProvided, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/provided/:providedId", h.DeleteImplementedRequirementByComponentExportProvided, guard.Delete())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/responsibilities", h.GetImplementedRequirementByComponentExportResponsibilities, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/responsibilities", h.CreateImplementedRequirementByComponentExportResponsibility, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/responsibilities/:responsibilityId", h.UpdateImplementedRequirementByComponentExportResponsibility, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId/export/responsibilities/:responsibilityId", h.DeleteImplementedRequirementByComponentExportResponsibility, guard.Delete())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export", h.GetImplementedRequirementStatementByComponentExport, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export", h.CreateImplementedRequirementStatementByComponentExport, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export", h.UpdateImplementedRequirementStatementByComponentExport, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export", h.DeleteImplementedRequirementStatementByComponentExport, guard.Delete())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/provided", h.GetImplementedRequirementStatementByComponentExportProvided, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/provided", h.CreateImplementedRequirementStatementByComponentExportProvided, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/provided/:providedId", h.UpdateImplementedRequirementStatementByComponentExportProvided, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/provided/:providedId", h.DeleteImplementedRequirementStatementByComponentExportProvided, guard.Delete())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/responsibilities", h.GetImplementedRequirementStatementByComponentExportResponsibilities, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/responsibilities", h.CreateImplementedRequirementStatementByComponentExportResponsibility, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/responsibilities/:responsibilityId", h.UpdateImplementedRequirementStatementByComponentExportResponsibility, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/export/responsibilities/:responsibilityId", h.DeleteImplementedRequirementStatementByComponentExportResponsibility, guard.Delete())

	// Consumer-side CRUD: statement-level only. Inherited/Satisfied describe what this
	// system consumes from an upstream and how it discharges the upstream's
	// responsibilities — both hang off a statement-anchored by-component by construction,
	// so they get no requirement-level surface.
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/inherited", h.GetImplementedRequirementStatementByComponentInherited, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/inherited", h.CreateImplementedRequirementStatementByComponentInherited, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/inherited/:inheritedId", h.UpdateImplementedRequirementStatementByComponentInherited, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/inherited/:inheritedId", h.DeleteImplementedRequirementStatementByComponentInherited, guard.Delete())
	api.GET("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/satisfied", h.GetImplementedRequirementStatementByComponentSatisfied, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/satisfied", h.CreateImplementedRequirementStatementByComponentSatisfied, guard.Create())
	api.PUT("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/satisfied/:satisfiedId", h.UpdateImplementedRequirementStatementByComponentSatisfied, guard.Update())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId/satisfied/:satisfiedId", h.DeleteImplementedRequirementStatementByComponentSatisfied, guard.Delete())

	api.GET("/:id/shared-responsibility", h.SharedResponsibility, guard.Read())
	api.DELETE("/:id/control-implementation/implemented-requirements/:reqId", h.DeleteImplementedRequirement, guard.Delete())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/suggest-components", h.SuggestComponents, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/apply-suggestion", h.ApplySuggestion, guard.Update())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/suggest-components", h.SuggestComponentsForStatement, guard.Read())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/apply-suggestion", h.ApplySuggestionForStatement, guard.Update())
	api.POST("/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/apply-suggestions", h.ApplySuggestionsForStatement, guard.Update())
	api.POST("/:id/bulk-apply-component-suggestions", h.BulkApplyComponentSuggestions, guard.Update())
	api.GET("/:id/back-matter", h.GetBackMatter, guard.Read())
	api.PUT("/:id/back-matter", h.UpdateBackMatter, guard.Update())
	api.GET("/:id/back-matter/resources", h.GetBackMatterResources, guard.Read())
	api.POST("/:id/back-matter/resources", h.CreateBackMatterResource, guard.Create())
	api.PUT("/:id/back-matter/resources/:resourceId", h.UpdateBackMatterResource, guard.Update())
	api.DELETE("/:id/back-matter/resources/:resourceId", h.DeleteBackMatterResource, guard.Delete())
}

// List godoc
//
//	@Summary		List System Security Plans
//	@Description	Retrieves all System Security Plans.
//	@Tags			System Security Plans
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans [get]
func (h *SystemSecurityPlanHandler) List(ctx echo.Context) error {
	var ssps []relational.SystemSecurityPlan

	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Find(&ssps).Error; err != nil {
		h.sugar.Error(err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalSSP := make([]oscalTypes_1_1_3.SystemSecurityPlan, len(ssps))
	for i, ssp := range ssps {
		oscalSSP[i] = *ssp.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: oscalSSP})
}

// Get godoc
//
//	@Summary		Get a System Security Plan
//	@Description	Retrieves a single System Security Plan by its unique ID.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id} [get]
func (h *SystemSecurityPlanHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.SystemSecurityPlan]{Data: ssp.MarshalOscal()})
}

// Create godoc
//
//	@Summary		Create a System Security Plan
//	@Description	Creates a System Security Plan from input.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			ssp	body		oscalTypes_1_1_3.SystemSecurityPlan	true	"SSP data"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans [post]
func (h *SystemSecurityPlanHandler) Create(ctx echo.Context) error {
	var oscalSSP oscalTypes_1_1_3.SystemSecurityPlan
	if err := ctx.Bind(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid create SSP request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateSSPInput(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid SSP input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	now := time.Now()
	relSSP := &relational.SystemSecurityPlan{}
	relSSP.UnmarshalOscal(oscalSSP)
	relSSP.Metadata.LastModified = &now
	relSSP.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if err := h.db.Create(relSSP).Error; err != nil {
		h.sugar.Errorf("Failed to create SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *relSSP.MarshalOscal()})
}

// GetCharacteristics godoc
//
//	@Summary		Get System Characteristics
//	@Description	Retrieves the System Characteristics for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics [get]
func (h *SystemSecurityPlanHandler) GetCharacteristics(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]{Data: ssp.MarshalOscal().SystemCharacteristics})
}

// GetCharacteristicsNetworkArchitecture godoc
//
//	@Summary		Get Network Architecture
//	@Description	Retrieves the Network Architecture for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.NetworkArchitecture]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/network-architecture [get]
func (h *SystemSecurityPlanHandler) GetCharacteristicsNetworkArchitecture(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.NetworkArchitecture").
		Preload("SystemCharacteristics.NetworkArchitecture.Diagrams").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	na := ssp.SystemCharacteristics.NetworkArchitecture
	if na == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no network architecture for system security plan %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.NetworkArchitecture]{Data: na.MarshalOscal()})
}

// CreateCharacteristicsNetworkArchitectureDiagram godoc
//
//	@Summary		Create a Network Architecture Diagram
//	@Description	Creates a new Diagram under the Network Architecture of a System Security Plan. Creates the Network Architecture grouping if it does not exist yet.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Diagram object to create"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/network-architecture/diagrams [post]
func (h *SystemSecurityPlanHandler) CreateCharacteristicsNetworkArchitectureDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Load SSP with Network Architecture so we can attach the diagram
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.NetworkArchitecture").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	na := ssp.SystemCharacteristics.NetworkArchitecture
	if na == nil || na.ID == nil {
		if ssp.SystemCharacteristics.ID == nil {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no system characteristics for system security plan %s", idParam)))
		}
		na = &relational.NetworkArchitecture{SystemCharacteristicsId: *ssp.SystemCharacteristics.ID}
		if err := h.db.Create(na).Error; err != nil {
			h.sugar.Errorf("Failed to create network architecture: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Bind incoming diagram
	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid create diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Basic UUID validation (consistent with other creates)
	if oscalDiag.UUID == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("UUID is required")))
	}
	if _, err := uuid.Parse(oscalDiag.UUID); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid UUID format: %v", err)))
	}

	// Map to relational model and set polymorphic parent
	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	parentID := na.ID.String()
	parentType := "network_architectures"
	relDiag.ParentID = &parentID
	relDiag.ParentType = &parentType

	if err := h.db.Create(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to create network architecture diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]{Data: *relDiag.MarshalOscal()})
}

// UpdateCharacteristicsNetworkArchitectureDiagram godoc
//
//	@Summary		Update a Network Architecture Diagram
//	@Description	Updates a specific Diagram under the Network Architecture of a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	path		string						true	"Diagram ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Updated Diagram object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/network-architecture/diagrams/{diagram} [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristicsNetworkArchitectureDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	_, err = uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.NetworkArchitecture").
		Preload("SystemCharacteristics.NetworkArchitecture.Diagrams").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	na := ssp.SystemCharacteristics.NetworkArchitecture
	if na == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no network architecture for system security plan %s", idParam)))
	}
	var existingDiag *relational.Diagram
	for _, diag := range na.Diagrams {
		if diag.ID.String() == diagramParam {
			d := diag
			existingDiag = &d
			break
		}
	}
	if existingDiag == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("diagram %s not found", diagramParam)))
	}
	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid update diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalDiag.UUID = existingDiag.ID.String()
	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	relDiag.ID = existingDiag.ID
	relDiag.ParentID = existingDiag.ParentID
	relDiag.ParentType = existingDiag.ParentType
	if err := h.db.Save(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to update network architecture diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Diagram]{Data: relDiag.MarshalOscal()})
}

// DeleteCharacteristicsNetworkArchitectureDiagram godoc
//
//	@Summary		Delete a Network Architecture Diagram
//	@Description	Deletes a specific Diagram under the Network Architecture of a System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id		path	string	true	"System Security Plan ID"
//	@Param			diagram	path	string	true	"Diagram ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/network-architecture/diagrams/{diagram} [delete]
func (h *SystemSecurityPlanHandler) DeleteCharacteristicsNetworkArchitectureDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	diagramID, err := uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.NetworkArchitecture").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	na := ssp.SystemCharacteristics.NetworkArchitecture
	if na == nil || na.ID == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no network architecture for system security plan %s", idParam)))
	}
	result := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", diagramID, na.ID, "network_architectures").Delete(&relational.Diagram{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete network architecture diagram: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("diagram not found")))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// GetCharacteristicsDataFlow godoc
//
//	@Summary		Get Data Flow
//	@Description	Retrieves the Data Flow for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.DataFlow]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/data-flow [get]
func (h *SystemSecurityPlanHandler) GetCharacteristicsDataFlow(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.DataFlow").
		Preload("SystemCharacteristics.DataFlow.Diagrams").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	na := ssp.SystemCharacteristics.DataFlow
	if na == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no network architecture for system security plan %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.DataFlow]{Data: na.MarshalOscal()})
}

// CreateCharacteristicsDataFlowDiagram godoc
//
//	@Summary		Create a Data Flow Diagram
//	@Description	Creates a new Diagram under the Data Flow of a System Security Plan. Creates the Data Flow grouping if it does not exist yet.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Diagram object to create"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/data-flow/diagrams [post]
func (h *SystemSecurityPlanHandler) CreateCharacteristicsDataFlowDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Load SSP with Data Flow
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.DataFlow").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	df := ssp.SystemCharacteristics.DataFlow
	if df == nil || df.ID == nil {
		if ssp.SystemCharacteristics.ID == nil {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no system characteristics for system security plan %s", idParam)))
		}
		df = &relational.DataFlow{SystemCharacteristicsId: *ssp.SystemCharacteristics.ID}
		if err := h.db.Create(df).Error; err != nil {
			h.sugar.Errorf("Failed to create data flow: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid create diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if oscalDiag.UUID == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("UUID is required")))
	}
	if _, err := uuid.Parse(oscalDiag.UUID); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid UUID format: %v", err)))
	}

	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	parentID := df.ID.String()
	parentType := "data_flows"
	relDiag.ParentID = &parentID
	relDiag.ParentType = &parentType

	if err := h.db.Create(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to create data flow diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]{Data: *relDiag.MarshalOscal()})
}

// UpdateCharacteristicsDataFlowDiagram godoc
//
//	@Summary		Update a Data Flow Diagram
//	@Description	Updates a specific Diagram under the Data Flow of a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	path		string						true	"Diagram ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Updated Diagram object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/data-flow/diagrams/{diagram} [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristicsDataFlowDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	_, err = uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.DataFlow").
		Preload("SystemCharacteristics.DataFlow.Diagrams").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	df := ssp.SystemCharacteristics.DataFlow
	if df == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no data flow for system security plan %s", idParam)))
	}
	var existingDiag *relational.Diagram
	for _, diag := range df.Diagrams {
		if diag.ID.String() == diagramParam {
			d := diag
			existingDiag = &d
			break
		}
	}
	if existingDiag == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("diagram %s not found", diagramParam)))
	}
	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid update diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalDiag.UUID = existingDiag.ID.String()
	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	relDiag.ID = existingDiag.ID
	relDiag.ParentID = existingDiag.ParentID
	relDiag.ParentType = existingDiag.ParentType
	if err := h.db.Save(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to update data flow diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Diagram]{Data: relDiag.MarshalOscal()})
}

// DeleteCharacteristicsDataFlowDiagram godoc
//
//	@Summary		Delete a Data Flow Diagram
//	@Description	Deletes a specific Diagram under the Data Flow of a System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id		path	string	true	"System Security Plan ID"
//	@Param			diagram	path	string	true	"Diagram ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/data-flow/diagrams/{diagram} [delete]
func (h *SystemSecurityPlanHandler) DeleteCharacteristicsDataFlowDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	diagramID, err := uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.DataFlow").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	df := ssp.SystemCharacteristics.DataFlow
	if df == nil || df.ID == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no data flow for system security plan %s", idParam)))
	}
	result := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", diagramID, df.ID, "data_flows").Delete(&relational.Diagram{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete data flow diagram: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("diagram not found")))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// GetCharacteristicsAuthorizationBoundary godoc
//
//	@Summary		Get Authorization Boundary
//	@Description	Retrieves the Authorization Boundary for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AuthorizationBoundary]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/authorization-boundary [get]
func (h *SystemSecurityPlanHandler) GetCharacteristicsAuthorizationBoundary(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.AuthorizationBoundary").
		Preload("SystemCharacteristics.AuthorizationBoundary.Diagrams").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	ab := ssp.SystemCharacteristics.AuthorizationBoundary
	if ab == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no authorization boundary for system security plan %s", idParam)))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.AuthorizationBoundary]{Data: ab.MarshalOscal()})
}

// CreateCharacteristicsAuthorizationBoundaryDiagram godoc
//
//	@Summary		Create an Authorization Boundary Diagram
//	@Description	Creates a new Diagram under the Authorization Boundary of a System Security Plan. Creates the Authorization Boundary grouping if it does not exist yet.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Diagram object to create"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/authorization-boundary/diagrams [post]
func (h *SystemSecurityPlanHandler) CreateCharacteristicsAuthorizationBoundaryDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Load SSP with Authorization Boundary
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.AuthorizationBoundary").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	ab := ssp.SystemCharacteristics.AuthorizationBoundary
	if ab == nil || ab.ID == nil {
		if ssp.SystemCharacteristics.ID == nil {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no system characteristics for system security plan %s", idParam)))
		}
		ab = &relational.AuthorizationBoundary{SystemCharacteristicsId: *ssp.SystemCharacteristics.ID}
		if err := h.db.Create(ab).Error; err != nil {
			h.sugar.Errorf("Failed to create authorization boundary: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid create diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if oscalDiag.UUID == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("UUID is required")))
	}
	if _, err := uuid.Parse(oscalDiag.UUID); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid UUID format: %v", err)))
	}

	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	parentID := ab.ID.String()
	parentType := "authorization_boundaries"
	relDiag.ParentID = &parentID
	relDiag.ParentType = &parentType

	if err := h.db.Create(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to create authorization boundary diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]{Data: *relDiag.MarshalOscal()})
}

// UpdateCharacteristicsAuthorizationBoundaryDiagram godoc
//
//	@Summary		Update an Authorization Boundary Diagram
//	@Description	Updates a specific Diagram under the Authorization Boundary of a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"System Security Plan ID"
//	@Param			diagram	path		string						true	"Diagram ID"
//	@Param			diagram	body		oscalTypes_1_1_3.Diagram	true	"Updated Diagram object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Diagram]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/authorization-boundary/diagrams/{diagram} [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristicsAuthorizationBoundaryDiagram(ctx echo.Context) error {

	// This is ugly for now, but it's safe and it works.
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	_, err = uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.AuthorizationBoundary").
		Preload("SystemCharacteristics.AuthorizationBoundary.Diagrams").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	ab := ssp.SystemCharacteristics.AuthorizationBoundary
	if ab == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no authorization boundary for system security plan %s", idParam)))
	}

	var existingDialog *relational.Diagram
	for _, diag := range ab.Diagrams {
		if diag.ID.String() == diagramParam {
			existingDialog = &diag
		}
	}
	if existingDialog == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	// Bind updated OSCAL diagram
	var oscalDiag oscalTypes_1_1_3.Diagram
	if err := ctx.Bind(&oscalDiag); err != nil {
		h.sugar.Warnw("Invalid update diagram request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	oscalDiag.UUID = existingDialog.ID.String()
	// Map to relational model
	relDiag := &relational.Diagram{}
	relDiag.UnmarshalOscal(oscalDiag)
	relDiag.ID = existingDialog.ID
	relDiag.ParentID = existingDialog.ParentID
	relDiag.ParentType = existingDialog.ParentType
	// Persist update
	if err := h.db.Save(relDiag).Error; err != nil {
		h.sugar.Errorf("Failed to update authorization boundary diagram: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Diagram]{Data: relDiag.MarshalOscal()})
}

// DeleteCharacteristicsAuthorizationBoundaryDiagram godoc
//
//	@Summary		Delete an Authorization Boundary Diagram
//	@Description	Deletes a specific Diagram under the Authorization Boundary of a System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id		path	string	true	"System Security Plan ID"
//	@Param			diagram	path	string	true	"Diagram ID"
//	@Success		204
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics/authorization-boundary/diagrams/{diagram} [delete]
func (h *SystemSecurityPlanHandler) DeleteCharacteristicsAuthorizationBoundaryDiagram(ctx echo.Context) error {
	idParam := ctx.Param("id")
	planID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	diagramParam := ctx.Param("diagram")
	diagramID, err := uuid.Parse(diagramParam)
	if err != nil {
		h.sugar.Warnw("Invalid diagram id", "diagram", diagramParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics.AuthorizationBoundary").
		First(&ssp, "id = ?", planID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	ab := ssp.SystemCharacteristics.AuthorizationBoundary
	if ab == nil || ab.ID == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no authorization boundary for system security plan %s", idParam)))
	}
	result := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", diagramID, ab.ID, "authorization_boundaries").Delete(&relational.Diagram{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete authorization boundary diagram: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("diagram not found")))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// UpdateCharacteristics godoc
//
//	@Summary		Update System Characteristics
//	@Description	Updates the System Characteristics for a given System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string									true	"System Security Plan ID"
//	@Param			characteristics	body		oscalTypes_1_1_3.SystemCharacteristics	true	"Updated System Characteristics object"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]
//	@Failure		400				{object}	api.Error
//	@Failure		401				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-characteristics [put]
func (h *SystemSecurityPlanHandler) UpdateCharacteristics(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalSC oscalTypes_1_1_3.SystemCharacteristics
	if err := ctx.Bind(&oscalSC); err != nil {
		h.sugar.Warnw("Invalid update system characteristics request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemCharacteristics").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	sc := &relational.SystemCharacteristics{}
	sc.UnmarshalOscal(oscalSC)

	sc.SystemSecurityPlanId = *ssp.ID
	sc.ID = ssp.SystemCharacteristics.ID

	// We do not want to update these subcomponents here.
	if err = h.db.Model(&sc).Omit("AuthorizationBoundary", "NetworkArchitecture", "DataFlow").Updates(&sc).Error; err != nil {
		h.sugar.Errorf("Failed to update system characteristics: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemCharacteristics]{Data: *sc.MarshalOscal()})
}

// GetSystemImplementation godoc
//
//	@Summary		Get System Implementation
//	@Description	Retrieves the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Load SystemImplementation separately with all its associations
	var si relational.SystemImplementation
	if err := h.db.
		Preload("Users").
		Preload("Users.AuthorizedPrivileges").
		Preload("Components").
		Preload("LeveragedAuthorizations").
		Preload("InventoryItems").
		Where("system_security_plan_id = ?", id).
		First(&si).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// SystemImplementation might not exist yet
			h.sugar.Infow("SystemImplementation not found for SSP", "sspId", id)
			return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]{Data: oscalTypes_1_1_3.SystemImplementation{}})
		}
		h.sugar.Warnw("Failed to load system implementation", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]{Data: *si.MarshalOscal()})
}

// GetSystemImplementationUsers godoc
//
//	@Summary		List System Implementation Users
//	@Description	Retrieves users in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.SystemUser]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationUsers(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.Users").
		Preload("SystemImplementation.Users.AuthorizedPrivileges").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SystemUser]{Data: ssp.MarshalOscal().SystemImplementation.Users})
}

// GetSystemImplementationComponents godoc
//
//	@Summary		List System Implementation Components
//	@Description	Retrieves components in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.Components").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.SystemComponent]{Data: ssp.MarshalOscal().SystemImplementation.Components})
}

// GetSystemImplementationComponent godoc
//
//	@Summary		Get System Implementation Component
//	@Description	Retrieves component in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id			path		string	true	"System Security Plan ID"
//	@Param			componentId	path		string	true	"Component ID"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components/{componentId} [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	componentId := ctx.Param("componentId")

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.Components", "id = ?", componentId).
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if len(ssp.SystemImplementation.Components) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]{Data: ssp.MarshalOscal().SystemImplementation.Components[0]})
}

// GetSystemImplementationInventoryItems godoc
//
//	@Summary		List System Implementation Inventory Items
//	@Description	Retrieves inventory items in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationInventoryItems(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.InventoryItems").
		Preload("SystemImplementation.InventoryItems.ImplementedComponents").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalSSP := ssp.MarshalOscal()
	if oscalSSP.SystemImplementation.InventoryItems == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]{Data: []oscalTypes_1_1_3.InventoryItem{}})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.InventoryItem]{Data: *oscalSSP.SystemImplementation.InventoryItems})
}

// GetSystemImplementationLeveragedAuthorizations godoc
//
//	@Summary		List System Implementation Leveraged Authorizations
//	@Description	Retrieves leveraged authorizations in the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations [get]
func (h *SystemSecurityPlanHandler) GetSystemImplementationLeveragedAuthorizations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("SystemImplementation").
		Preload("SystemImplementation.LeveragedAuthorizations").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalSSP := ssp.MarshalOscal()
	if oscalSSP.SystemImplementation.LeveragedAuthorizations == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: []oscalTypes_1_1_3.LeveragedAuthorization{}})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: *oscalSSP.SystemImplementation.LeveragedAuthorizations})
}

// GetControlImplementation godoc
//
//	@Summary		Get Control Implementation
//	@Description	Retrieves the Control Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation [get]
func (h *SystemSecurityPlanHandler) GetControlImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("ControlImplementation").
		Preload("Profiles").
		First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Determine if we need to filter by bound profiles
	controlIDs, err := h.getControlIDsForAllProfiles(ssp.Profiles)
	if err != nil {
		h.sugar.Warnw("Failed to resolve profile controls", "sspID", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	query := h.db.Model(&ssp.ControlImplementation).
		Preload("ImplementedRequirements", func(db *gorm.DB) *gorm.DB {
			if len(controlIDs) > 0 {
				// controlIDs carry canonical casing; lower them for the IN match.
				return db.Where("LOWER(control_id) IN ?", normalizeControlIDs(controlIDs))
			}
			return db
		}).
		Preload("ImplementedRequirements.ByComponents").
		Preload("ImplementedRequirements.ByComponents.Export").
		Preload("ImplementedRequirements.ByComponents.Export.Provided").
		Preload("ImplementedRequirements.ByComponents.Export.Responsibilities").
		Preload("ImplementedRequirements.ByComponents.Inherited").
		Preload("ImplementedRequirements.ByComponents.Satisfied").
		Preload("ImplementedRequirements.Statements").
		Preload("ImplementedRequirements.Statements.ByComponents").
		Preload("ImplementedRequirements.Statements.ByComponents.Export").
		Preload("ImplementedRequirements.Statements.ByComponents.Export.Provided").
		Preload("ImplementedRequirements.Statements.ByComponents.Export.Responsibilities").
		Preload("ImplementedRequirements.Statements.ByComponents.Inherited").
		Preload("ImplementedRequirements.Statements.ByComponents.Satisfied")

	if err := query.First(&ssp.ControlImplementation).Error; err != nil {
		h.sugar.Warnw("Failed to load control implementation", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]{Data: ssp.MarshalOscal().ControlImplementation})
}

func (h *SystemSecurityPlanHandler) Full(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid ssp id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("Profiles").
		First(&ssp, "id = ?", id.String()).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load ssp", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Determine if we need to filter by bound profiles
	controlIDs, err := h.getControlIDsForAllProfiles(ssp.Profiles)
	if err != nil {
		h.sugar.Warnw(
			"Failed to get control IDs for profiles; returning unfiltered control implementation",
			"sspID", id,
			"error", err,
		)
	}

	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Metadata.Roles").
		Preload("Metadata.Parties").
		Preload("Metadata.Parties.Locations").
		Preload("Metadata.Parties.MemberOfOrganizations").
		Preload("Metadata.ResponsibleParties").
		Preload("Metadata.ResponsibleParties.Parties").
		Preload("Metadata.Locations").
		Preload("Metadata.Actions").
		Preload("Metadata.Actions.ResponsibleParties").
		Preload("Metadata.Actions.ResponsibleParties.Parties").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Preload("ControlImplementation").
		Preload("ControlImplementation.ImplementedRequirements", func(db *gorm.DB) *gorm.DB {
			if len(controlIDs) > 0 {
				// controlIDs carry canonical casing; lower them for the IN match.
				return db.Where("LOWER(control_id) IN ?", normalizeControlIDs(controlIDs))
			}
			return db
		}).
		Preload("ControlImplementation.ImplementedRequirements.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Provided").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Provided.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Provided.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Responsibilities").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Responsibilities.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Responsibilities.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Inherited").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Inherited.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Inherited.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Satisfied").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Satisfied.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Satisfied.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Provided").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Provided.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Provided.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Responsibilities").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Responsibilities.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Responsibilities.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied.ResponsibleRoles.Parties").
		Preload("SystemCharacteristics").
		Preload("SystemCharacteristics.AuthorizationBoundary").
		Preload("SystemCharacteristics.AuthorizationBoundary.Diagrams").
		Preload("SystemCharacteristics.NetworkArchitecture").
		Preload("SystemCharacteristics.NetworkArchitecture.Diagrams").
		Preload("SystemCharacteristics.DataFlow").
		Preload("SystemCharacteristics.DataFlow.Diagrams").
		Preload("SystemImplementation").
		Preload("SystemImplementation.Users").
		Preload("SystemImplementation.Users.AuthorizedPrivileges").
		Preload("SystemImplementation.LeveragedAuthorizations").
		Preload("SystemImplementation.Components").
		Preload("SystemImplementation.Components.ResponsibleRoles").
		Preload("SystemImplementation.Components.ResponsibleRoles.Parties").
		Preload("SystemImplementation.InventoryItems").
		Preload("SystemImplementation.InventoryItems.ImplementedComponents").
		First(&ssp, "id = ?", id.String()).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load ssp", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *ssp.MarshalOscal()})
}

// Update godoc
//
//	@Summary		Update a System Security Plan
//	@Description	Updates an existing System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string								true	"SSP ID"
//	@Param			ssp	body		oscalTypes_1_1_3.SystemSecurityPlan	true	"SSP data"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id} [put]
func (h *SystemSecurityPlanHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalSSP oscalTypes_1_1_3.SystemSecurityPlan
	if err := ctx.Bind(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid update SSP request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateSSPInput(&oscalSSP); err != nil {
		h.sugar.Warnw("Invalid SSP input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	now := time.Now()
	relSSP := &relational.SystemSecurityPlan{}
	relSSP.UnmarshalOscal(oscalSSP)
	relSSP.ID = &id
	relSSP.Metadata.LastModified = &now
	relSSP.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if err := h.db.Model(relSSP).Where("id = ?", id).Updates(relSSP).Error; err != nil {
		h.sugar.Errorf("Failed to update SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *relSSP.MarshalOscal()})
}

// Delete godoc
//
//	@Summary		Delete a System Security Plan
//	@Description	Deletes an existing System Security Plan and all its related data.
//	@Tags			System Security Plans
//	@Param			id	path	string	true	"SSP ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id} [delete]
func (h *SystemSecurityPlanHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Delete(&existingSSP).Error; err != nil {
		h.sugar.Errorf("Failed to delete SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetMetadata godoc
//
//	@Summary		Get SSP metadata
//	@Description	Retrieves metadata for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/metadata [get]
func (h *SystemSecurityPlanHandler) GetMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("Metadata").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	metadata := ssp.Metadata.MarshalOscal()
	if metadata == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no metadata for SSP %s", idParam)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]{Data: *metadata})
}

// UpdateMetadata godoc
//
//	@Summary		Update SSP metadata
//	@Description	Updates metadata for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			metadata	body		oscalTypes_1_1_3.Metadata	true	"Metadata data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/metadata [put]
func (h *SystemSecurityPlanHandler) UpdateMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalMetadata oscalTypes_1_1_3.Metadata
	if err := ctx.Bind(&oscalMetadata); err != nil {
		h.sugar.Warnw("Invalid update metadata request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("Metadata").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	now := time.Now()
	relMetadata := &relational.Metadata{}
	relMetadata.UnmarshalOscal(oscalMetadata)
	relMetadata.LastModified = &now
	relMetadata.OscalVersion = versioning.GetLatestSupportedVersion()
	relMetadata.ID = ssp.Metadata.ID
	sspIDStr := ssp.ID.String()
	parentType := "system_security_plans"
	relMetadata.ParentID = &sspIDStr
	relMetadata.ParentType = &parentType

	if err := h.db.Save(relMetadata).Error; err != nil {
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]{Data: *relMetadata.MarshalOscal()})
}

// GetProfile godoc
//
//	@Summary		Get Profile for a System Security Plan
//	@Description	Retrieves the Profile attached to the specified System Security Plan.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Profile]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/profile [get]
func (h *SystemSecurityPlanHandler) GetProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP ID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("Profiles").
		Preload("Profiles.Metadata").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorf("Failed to fetch SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if len(ssp.Profiles) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("no profile attached")))
	}

	if len(ssp.Profiles) > 1 {
		err := errors.New("multiple profiles attached; use the profiles endpoint or detach extra profiles")
		h.sugar.Warnw("Ambiguous profile lookup for legacy single-profile endpoint", "ssp_id", sspID, "profile_count", len(ssp.Profiles))
		return ctx.JSON(http.StatusConflict, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Profile]{Data: ssp.Profiles[0].MarshalOscal()})
}

// AttachProfile godoc
//
//	@Summary		Attach a Profile to a System Security Plan
//	@Description	Associates a given Profile with a System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"SSP ID"
//	@Param			request	body		addProfileRequest	true	"Profile binding request"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/profile [put]
func (h *SystemSecurityPlanHandler) AttachProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var input addProfileRequest
	if err := ctx.Bind(&input); err != nil {
		h.sugar.Warnw("Invalid profile ID input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profileID, err := uuid.Parse(input.ProfileID)
	if err != nil {
		h.sugar.Warnw("Invalid profile ID format", "profileId", input.ProfileID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").Preload("Profiles").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("Failed to load SSP", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Load the profile basic info
	var profile relational.Profile
	if err := h.db.First(&profile, "id = ?", profileID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("profile not found")))
		}
		h.sugar.Errorw("Failed to load profile", "profileId", profileID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Use the optimized resolution path
	controlIDs, err := h.getControlIDsForProfile(profileID)
	if err != nil {
		h.sugar.Warnw("Failed to resolve control IDs for profile", "profileId", profileID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("failed to resolve control IDs for profile: %w", err)))
	}

	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Sync the join table: clear existing rows and insert the new profile.
		// This keeps the legacy single-profile PUT semantics (replace, not append).
		if err := tx.Where("system_security_plan_id = ?", sspID).
			Delete(&relational.SSPProfile{}).Error; err != nil {
			return fmt.Errorf("failed to clear ssp_profiles: %w", err)
		}
		if err := tx.Create(&relational.SSPProfile{
			SystemSecurityPlanID: sspID,
			ProfileID:            profileID,
		}).Error; err != nil {
			return fmt.Errorf("failed to insert ssp_profiles row: %w", err)
		}

		// Ensure ControlImplementation exists for the SSP
		if ssp.ControlImplementation.ID == nil {
			newID := uuid.New()
			ssp.ControlImplementation = relational.ControlImplementation{
				UUIDModel:            relational.UUIDModel{ID: &newID},
				Description:          "Control implementation",
				SystemSecurityPlanId: *ssp.ID,
			}
			if err := tx.Create(&ssp.ControlImplementation).Error; err != nil {
				return err
			}
		}

		// If no controls were resolved for the attached profile, treat this as a failure
		// and roll back the SSP update to avoid an inconsistent state.
		if len(controlIDs) == 0 {
			return errors.New("no controls were resolved from the selected profile; rolling back SSP update")
		}

		// Bulk operations for ImplementedRequirements
		var existingControlIDs []string
		if err := tx.Model(&relational.ImplementedRequirement{}).
			Where("control_implementation_id = ?", ssp.ControlImplementation.ID).
			Pluck("control_id", &existingControlIDs).Error; err != nil {
			return err
		}

		existingMap := make(map[string]bool)
		for _, id := range existingControlIDs {
			existingMap[normalizeControlID(id)] = true
		}

		var newReqs []relational.ImplementedRequirement
		for _, controlID := range controlIDs {
			// Dedupe case-insensitively, but persist the canonical casing.
			if !existingMap[normalizeControlID(controlID)] {
				newUUID := uuid.New()
				newReqs = append(newReqs, relational.ImplementedRequirement{
					UUIDModel:               relational.UUIDModel{ID: &newUUID},
					ControlImplementationId: *ssp.ControlImplementation.ID,
					ControlId:               controlID,
				})
			}
		}

		if len(newReqs) > 0 {
			if err := tx.Create(&newReqs).Error; err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		h.sugar.Errorf("Failed to attach profile to SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Enqueue orphaned risk cleanup after the transaction commits successfully.
	if h.jobEnqueuer != nil {
		enqueueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request().Context()), 10*time.Second)
		defer cancel()
		// Replacement cleanup resolves the current bound profiles at execution time.
		// Keep oldProfileID nil so equivalent replacements dedupe consistently even
		// when the previous M:M profile order is nondeterministic.
		if err := h.jobEnqueuer.EnqueueOrphanedRiskCleanup(enqueueCtx, sspID, nil, &profileID); err != nil {
			h.sugar.Warnw("Failed to enqueue orphaned risk cleanup job", "sspId", sspID, "error", err)
		}
	}

	// Reload SSP to ensure the memory state matches the database (including newly created requirements)
	if err := h.db.Preload("ControlImplementation.ImplementedRequirements").First(&ssp, "id = ?", ssp.ID).Error; err != nil {
		h.sugar.Errorw("Failed to reload SSP after profile attachment", "id", ssp.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(fmt.Errorf("failed to reload system security plan after profile attachment")))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemSecurityPlan]{Data: *ssp.MarshalOscal()})
}

// ListProfiles godoc
//
//	@Summary		List Profiles bound to an SSP
//	@Description	Returns all profiles associated with a System Security Plan via the ssp_profiles join table.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[profileSummary]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/profiles [get]
func (h *SystemSecurityPlanHandler) ListProfiles(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP ID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.
		Preload("Profiles").
		Preload("Profiles.Metadata").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorf("Failed to fetch SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	summaries, err := buildProfileSummaries(ssp.Profiles)
	if err != nil {
		h.sugar.Errorw("Failed to build profile summaries", "sspId", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[profileSummary]{Data: summaries})
}

// AddProfile godoc
//
//	@Summary		Add a Profile binding to an SSP
//	@Description	Associates an additional Profile with a System Security Plan. Creates ImplementedRequirements for any new controls.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"SSP ID"
//	@Param			request	body		addProfileRequest	true	"Profile binding request"
//	@Success		200		{object}	handler.GenericDataListResponse[profileSummary]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/profiles [post]
func (h *SystemSecurityPlanHandler) AddProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP ID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var input addProfileRequest
	if err := ctx.Bind(&input); err != nil {
		h.sugar.Warnw("Invalid profile ID input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profileID, err := uuid.Parse(input.ProfileID)
	if err != nil {
		h.sugar.Warnw("Invalid profile ID format", "profileId", input.ProfileID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("Failed to load SSP", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check profile exists
	var profile relational.Profile
	if err := h.db.First(&profile, "id = ?", profileID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("profile not found")))
		}
		h.sugar.Errorw("Failed to load profile", "profileId", profileID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var duplicateBinding bool
	errNoResolvedControls := errors.New("no controls were resolved from the selected profile")
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Insert join-table row idempotently; ON CONFLICT DO NOTHING avoids a TOCTOU race.
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&relational.SSPProfile{
			SystemSecurityPlanID: sspID,
			ProfileID:            profileID,
		})
		if result.Error != nil {
			return fmt.Errorf("failed to insert ssp_profiles row: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			duplicateBinding = true
			return nil
		}

		controlIDs, err := h.getControlIDsForProfile(profileID)
		if err != nil {
			return fmt.Errorf("failed to resolve control IDs for profile: %w", err)
		}
		if len(controlIDs) == 0 {
			return errNoResolvedControls
		}

		// Ensure ControlImplementation exists
		if ssp.ControlImplementation.ID == nil {
			newID := uuid.New()
			ssp.ControlImplementation = relational.ControlImplementation{
				UUIDModel:            relational.UUIDModel{ID: &newID},
				Description:          "Control implementation",
				SystemSecurityPlanId: *ssp.ID,
			}
			if err := tx.Create(&ssp.ControlImplementation).Error; err != nil {
				return err
			}
		}

		// Add any new ImplementedRequirements for the profile's controls
		var existingControlIDs []string
		if err := tx.Model(&relational.ImplementedRequirement{}).
			Where("control_implementation_id = ?", ssp.ControlImplementation.ID).
			Pluck("control_id", &existingControlIDs).Error; err != nil {
			return err
		}

		existingMap := make(map[string]bool, len(existingControlIDs))
		for _, id := range existingControlIDs {
			existingMap[normalizeControlID(id)] = true
		}

		var newReqs []relational.ImplementedRequirement
		for _, controlID := range controlIDs {
			// Dedupe case-insensitively, but persist the canonical casing.
			if !existingMap[normalizeControlID(controlID)] {
				newUUID := uuid.New()
				newReqs = append(newReqs, relational.ImplementedRequirement{
					UUIDModel:               relational.UUIDModel{ID: &newUUID},
					ControlImplementationId: *ssp.ControlImplementation.ID,
					ControlId:               controlID,
				})
			}
		}

		if len(newReqs) > 0 {
			if err := tx.Create(&newReqs).Error; err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		if errors.Is(err, errNoResolvedControls) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(errNoResolvedControls))
		}
		h.sugar.Errorf("Failed to add profile to SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if duplicateBinding {
		return ctx.JSON(http.StatusConflict, api.NewError(fmt.Errorf("profile %s is already bound to this SSP", profileID)))
	}

	// Enqueue orphaned risk cleanup
	if h.jobEnqueuer != nil {
		enqueueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request().Context()), 10*time.Second)
		defer cancel()
		if err := h.jobEnqueuer.EnqueueOrphanedRiskCleanup(enqueueCtx, sspID, nil, &profileID); err != nil {
			h.sugar.Warnw("Failed to enqueue orphaned risk cleanup job", "sspId", sspID, "error", err)
		}
	}

	// Return updated profile list
	var updated relational.SystemSecurityPlan
	if err := h.db.Preload("Profiles").Preload("Profiles.Metadata").First(&updated, "id = ?", sspID).Error; err != nil {
		h.sugar.Errorw("Failed to reload SSP after adding profile", "id", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	summaries, err := buildProfileSummaries(updated.Profiles)
	if err != nil {
		h.sugar.Errorw("Failed to build profile summaries after adding profile", "sspId", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[profileSummary]{Data: summaries})
}

// RemoveProfile godoc
//
//	@Summary		Remove a Profile binding from an SSP
//	@Description	Removes a profile association from a System Security Plan. Enqueues orphaned risk cleanup.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id			path		string	true	"SSP ID"
//	@Param			profileId	path		string	true	"Profile ID to remove"
//	@Success		200			{object}	handler.GenericDataListResponse[profileSummary]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/profiles/{profileId} [delete]
func (h *SystemSecurityPlanHandler) RemoveProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP ID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profileIDParam := ctx.Param("profileId")
	profileID, err := uuid.Parse(profileIDParam)
	if err != nil {
		h.sugar.Warnw("Invalid profile ID", "profileId", profileIDParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify SSP exists
	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete the join-table row
	result := h.db.Where("system_security_plan_id = ? AND profile_id = ?", sspID, profileID).
		Delete(&relational.SSPProfile{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to remove profile from SSP: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("profile %s is not bound to this SSP", profileID)))
	}

	// Enqueue orphaned risk cleanup
	if h.jobEnqueuer != nil {
		enqueueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request().Context()), 10*time.Second)
		defer cancel()
		if err := h.jobEnqueuer.EnqueueOrphanedRiskCleanup(enqueueCtx, sspID, &profileID, nil); err != nil {
			h.sugar.Warnw("Failed to enqueue orphaned risk cleanup job", "sspId", sspID, "error", err)
		}
	}

	// Return updated profile list
	var updated relational.SystemSecurityPlan
	if err := h.db.Preload("Profiles").Preload("Profiles.Metadata").First(&updated, "id = ?", sspID).Error; err != nil {
		h.sugar.Errorw("Failed to reload SSP after removing profile", "id", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	summaries, err := buildProfileSummaries(updated.Profiles)
	if err != nil {
		h.sugar.Errorw("Failed to build profile summaries after removing profile", "sspId", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[profileSummary]{Data: summaries})
}

// GetImportProfile godoc
//
//	@Summary		Get SSP import-profile
//	@Description	Retrieves import-profile for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/import-profile [get]
func (h *SystemSecurityPlanHandler) GetImportProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	importProfile := ssp.ImportProfile.Data()
	if importProfile.Href == "" {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no import-profile for SSP %s", idParam)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]{Data: *importProfile.MarshalOscal()})
}

// UpdateImportProfile godoc
//
//	@Summary		Update SSP import-profile
//	@Description	Updates import-profile for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string							true	"SSP ID"
//	@Param			import-profile	body		oscalTypes_1_1_3.ImportProfile	true	"Import Profile data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/import-profile [put]
func (h *SystemSecurityPlanHandler) UpdateImportProfile(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalImportProfile oscalTypes_1_1_3.ImportProfile
	if err := ctx.Bind(&oscalImportProfile); err != nil {
		h.sugar.Warnw("Invalid update import-profile request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relImportProfile := &relational.ImportProfile{}
	relImportProfile.UnmarshalOscal(oscalImportProfile)

	// Update the ImportProfile field in the SSP
	ssp.ImportProfile = datatypes.NewJSONType(*relImportProfile)

	// Save the updated SSP.
	// UpdateImportProfile only updates the href metadata field (import-profile.href).
	// It does NOT change ssp.ProfileID — the actual profile binding FK — so no controls
	// are added or removed and no orphaned risk cleanup is required.
	if err := h.db.Save(&ssp).Error; err != nil {
		h.sugar.Errorf("Failed to update import-profile: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportProfile]{Data: *relImportProfile.MarshalOscal()})
}

// UpdateSystemImplementation godoc
//
//	@Summary		Update System Implementation
//	@Description	Updates the System Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string									true	"System Security Plan ID"
//	@Param			system-implementation	body		oscalTypes_1_1_3.SystemImplementation	true	"Updated System Implementation object"
//	@Success		200						{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/system-implementation [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalSI oscalTypes_1_1_3.SystemImplementation
	if err := ctx.Bind(&oscalSI); err != nil {
		h.sugar.Warnw("Invalid update system implementation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("SystemImplementation").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	si := &relational.SystemImplementation{}
	si.UnmarshalOscal(oscalSI)
	si.SystemSecurityPlanId = *ssp.ID
	si.ID = ssp.SystemImplementation.ID

	// Use Save instead of Updates to ensure all fields are properly saved
	if err := h.db.Save(&si).Error; err != nil {
		h.sugar.Errorf("Failed to update system implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Reload the updated system implementation from database to get the latest data with all associations
	var updatedSI relational.SystemImplementation
	if err := h.db.
		Preload("Users").
		Preload("Users.AuthorizedPrivileges").
		Preload("Components").
		Preload("LeveragedAuthorizations").
		Preload("InventoryItems").
		Preload("InventoryItems.ImplementedComponents").
		First(&updatedSI, "id = ?", si.ID).Error; err != nil {
		h.sugar.Errorf("Failed to reload updated system implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemImplementation]{Data: *updatedSI.MarshalOscal()})
}

// CreateSystemImplementationUser godoc
//
//	@Summary		Create a new system user
//	@Description	Creates a new system user for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"SSP ID"
//	@Param			user	body		oscalTypes_1_1_3.SystemUser	true	"System User data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationUser(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var oscalUser oscalTypes_1_1_3.SystemUser
	if err := ctx.Bind(&oscalUser); err != nil {
		h.sugar.Warnw("Invalid create user request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateSystemUserInput(&oscalUser); err != nil {
		h.sugar.Warnw("Invalid user input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relUser := &relational.SystemUser{}
	relUser.UnmarshalOscal(oscalUser)
	relUser.SystemImplementationId = *systemImpl.ID

	if err := h.db.Create(relUser).Error; err != nil {
		h.sugar.Errorf("Failed to create user: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]{Data: *relUser.MarshalOscal()})
}

// UpdateSystemImplementationUser godoc
//
//	@Summary		Update a system user
//	@Description	Updates an existing system user for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"SSP ID"
//	@Param			userId	path		string						true	"User ID"
//	@Param			user	body		oscalTypes_1_1_3.SystemUser	true	"System User data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users/{userId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationUser(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	userIdParam := ctx.Param("userId")
	userID, err := uuid.Parse(userIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid user id", "userId", userIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingUser relational.SystemUser
	if err := h.db.Where("id = ? AND system_implementation_id = ?", userID, *systemImpl.ID).First(&existingUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find user: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalUser oscalTypes_1_1_3.SystemUser
	if err := ctx.Bind(&oscalUser); err != nil {
		h.sugar.Warnw("Invalid update user request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relUser := &relational.SystemUser{}
	relUser.UnmarshalOscal(oscalUser)
	relUser.SystemImplementationId = *systemImpl.ID
	relUser.ID = &userID

	if err := h.db.Save(relUser).Error; err != nil {
		h.sugar.Errorf("Failed to update user: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemUser]{Data: *relUser.MarshalOscal()})
}

// DeleteSystemImplementationUser godoc
//
//	@Summary		Delete a system user
//	@Description	Deletes an existing system user for a given SSP.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			userId	path	string	true	"User ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/users/{userId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationUser(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	userIdParam := ctx.Param("userId")
	userID, err := uuid.Parse(userIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid user id", "userId", userIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	result := h.db.Where("id = ? AND system_implementation_id = ?", userID, *systemImpl.ID).Delete(&relational.SystemUser{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete user: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("user not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateSystemImplementationComponent godoc
//
//	@Summary		Create a new system component
//	@Description	Creates a new system component for a given SSP. Accepts an optional definedComponentId field to link to a DefinedComponent.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"SSP ID"
//	@Param			component	body		SystemComponentRequest	true	"System Component data with optional definedComponentId field"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var req SystemComponentRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Warnw("Invalid create component request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateSystemComponentInput(&req.SystemComponent); err != nil {
		h.sugar.Warnw("Invalid component input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relComponent := &relational.SystemComponent{}
	relComponent.UnmarshalOscal(req.SystemComponent)
	relComponent.SystemImplementationId = *systemImpl.ID
	relComponent.DefinedComponentID = req.DefinedComponentID

	if err := h.db.Create(relComponent).Error; err != nil {
		h.sugar.Errorf("Failed to create component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]{Data: *relComponent.MarshalOscal()})
}

// UpdateSystemImplementationComponent godoc
//
//	@Summary		Update a system component
//	@Description	Updates an existing system component for a given SSP. Accepts an optional definedComponentId field to link to a DefinedComponent.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"SSP ID"
//	@Param			componentId	path		string					true	"Component ID"
//	@Param			component	body		SystemComponentRequest	true	"System Component data with optional definedComponentId field"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components/{componentId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	componentIdParam := ctx.Param("componentId")
	componentID, err := uuid.Parse(componentIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid component id", "componentId", componentIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingComponent relational.SystemComponent
	if err := h.db.Where("id = ? AND system_implementation_id = ?", componentID, *systemImpl.ID).First(&existingComponent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var req SystemComponentRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Warnw("Invalid update component request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relComponent := &relational.SystemComponent{}
	relComponent.UnmarshalOscal(req.SystemComponent)
	relComponent.SystemImplementationId = *systemImpl.ID
	relComponent.ID = &componentID
	// Only update DefinedComponentID if explicitly provided in request
	// This prevents clearing existing links when clients omit the field
	if req.DefinedComponentID != nil {
		relComponent.DefinedComponentID = req.DefinedComponentID
	} else {
		relComponent.DefinedComponentID = existingComponent.DefinedComponentID
	}

	if err := h.db.Save(relComponent).Error; err != nil {
		h.sugar.Errorf("Failed to update component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.SystemComponent]{Data: *relComponent.MarshalOscal()})
}

// DeleteSystemImplementationComponent godoc
//
//	@Summary		Delete a system component
//	@Description	Deletes an existing system component for a given SSP.
//	@Tags			System Security Plans
//	@Param			id			path	string	true	"SSP ID"
//	@Param			componentId	path	string	true	"Component ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/components/{componentId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	componentIdParam := ctx.Param("componentId")
	componentID, err := uuid.Parse(componentIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid component id", "componentId", componentIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var componentNotFound bool
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&riskrel.RiskComponentLink{}, "component_id = ?", componentID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&relational.ByComponent{}, "component_uuid = ?", componentID).Error; err != nil {
			return err
		}

		result := tx.Where("id = ? AND system_implementation_id = ?", componentID, *systemImpl.ID).Delete(&relational.SystemComponent{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			componentNotFound = true
			return gorm.ErrRecordNotFound
		}

		return nil
	}); err != nil {
		if componentNotFound || errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("component not found")))
		}
		h.sugar.Errorf("Failed to delete component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateSystemImplementationInventoryItem godoc
//
//	@Summary		Create a new inventory item
//	@Description	Creates a new inventory item for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"SSP ID"
//	@Param			item	body		oscalTypes_1_1_3.InventoryItem	true	"Inventory Item data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationInventoryItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var oscalItem oscalTypes_1_1_3.InventoryItem
	if err := ctx.Bind(&oscalItem); err != nil {
		h.sugar.Warnw("Invalid create inventory item request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateInventoryItemInput(&oscalItem); err != nil {
		h.sugar.Warnw("Invalid inventory item input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relItem := &relational.InventoryItem{}
	relItem.UnmarshalOscal(oscalItem)
	relItem.SystemImplementationId = *systemImpl.ID

	if err := h.db.Create(relItem).Error; err != nil {
		h.sugar.Errorf("Failed to create inventory item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]{Data: relItem.MarshalOscal()})
}

// UpdateSystemImplementationInventoryItem godoc
//
//	@Summary		Update an inventory item
//	@Description	Updates an existing inventory item for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"SSP ID"
//	@Param			itemId	path		string							true	"Item ID"
//	@Param			item	body		oscalTypes_1_1_3.InventoryItem	true	"Inventory Item data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items/{itemId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationInventoryItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	itemIdParam := ctx.Param("itemId")
	itemID, err := uuid.Parse(itemIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid item id", "itemId", itemIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingItem relational.InventoryItem
	if err := h.db.Where("id = ? AND system_implementation_id = ?", itemID, *systemImpl.ID).First(&existingItem).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find inventory item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalItem oscalTypes_1_1_3.InventoryItem
	if err := ctx.Bind(&oscalItem); err != nil {
		h.sugar.Warnw("Invalid update inventory item request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relItem := &relational.InventoryItem{}
	relItem.UnmarshalOscal(oscalItem)

	relItem.SystemImplementationId = *systemImpl.ID
	relItem.ID = &itemID

	if err := h.db.Save(relItem).Error; err != nil {
		h.sugar.Errorf("Failed to update inventory item: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.InventoryItem]{Data: relItem.MarshalOscal()})
}

// DeleteSystemImplementationInventoryItem godoc
//
//	@Summary		Delete an inventory item
//	@Description	Deletes an existing inventory item for a given SSP.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			itemId	path	string	true	"Item ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/inventory-items/{itemId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationInventoryItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	itemIdParam := ctx.Param("itemId")
	itemID, err := uuid.Parse(itemIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid item id", "itemId", itemIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	result := h.db.Where("id = ? AND system_implementation_id = ?", itemID, *systemImpl.ID).Delete(&relational.InventoryItem{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete inventory item: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("inventory item not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateSystemImplementationLeveragedAuthorization godoc
//
//	@Summary		Create a new leveraged authorization
//	@Description	Creates a new leveraged authorization for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string									true	"SSP ID"
//	@Param			auth	body		oscalTypes_1_1_3.LeveragedAuthorization	true	"Leveraged Authorization data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations [post]
func (h *SystemSecurityPlanHandler) CreateSystemImplementationLeveragedAuthorization(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", id).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", id, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var oscalAuth oscalTypes_1_1_3.LeveragedAuthorization
	if err := ctx.Bind(&oscalAuth); err != nil {
		h.sugar.Warnw("Invalid create leveraged authorization request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relAuth := &relational.LeveragedAuthorization{}
	relAuth.UnmarshalOscal(oscalAuth)
	relAuth.SystemImplementationId = *systemImpl.ID

	if err := h.db.Create(relAuth).Error; err != nil {
		h.sugar.Errorf("Failed to create leveraged authorization: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: *relAuth.MarshalOscal()})
}

// UpdateSystemImplementationLeveragedAuthorization godoc
//
//	@Summary		Update a leveraged authorization
//	@Description	Updates an existing leveraged authorization for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string									true	"SSP ID"
//	@Param			authId	path		string									true	"Authorization ID"
//	@Param			auth	body		oscalTypes_1_1_3.LeveragedAuthorization	true	"Leveraged Authorization data"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations/{authId} [put]
func (h *SystemSecurityPlanHandler) UpdateSystemImplementationLeveragedAuthorization(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	authIdParam := ctx.Param("authId")
	authID, err := uuid.Parse(authIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid authorization id", "authId", authIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var existingAuth relational.LeveragedAuthorization
	if err := h.db.Where("id = ? AND system_implementation_id = ?", authID, *systemImpl.ID).First(&existingAuth).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find leveraged authorization: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalAuth oscalTypes_1_1_3.LeveragedAuthorization
	if err := ctx.Bind(&oscalAuth); err != nil {
		h.sugar.Warnw("Invalid update leveraged authorization request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relAuth := &relational.LeveragedAuthorization{}
	relAuth.UnmarshalOscal(oscalAuth)
	relAuth.SystemImplementationId = *systemImpl.ID
	relAuth.ID = &authID

	if err := h.db.Save(relAuth).Error; err != nil {
		h.sugar.Errorf("Failed to update leveraged authorization: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.LeveragedAuthorization]{Data: *relAuth.MarshalOscal()})
}

// DeleteSystemImplementationLeveragedAuthorization godoc
//
//	@Summary		Delete a leveraged authorization
//	@Description	Deletes an existing leveraged authorization for a given SSP.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			authId	path	string	true	"Authorization ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/system-implementation/leveraged-authorizations/{authId} [delete]
func (h *SystemSecurityPlanHandler) DeleteSystemImplementationLeveragedAuthorization(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	authIdParam := ctx.Param("authId")
	authID, err := uuid.Parse(authIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid authorization id", "authId", authIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Get the system implementation ID directly from the database
	var systemImpl relational.SystemImplementation
	if err := h.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		h.sugar.Errorw("failed to get system implementation", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	var driftedLinks []driftedLinkInfo
	var rowsAffected int64
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Where("id = ? AND system_implementation_id = ?", authID, *systemImpl.ID).Delete(&relational.LeveragedAuthorization{})
		if result.Error != nil {
			return result.Error
		}
		rowsAffected = result.RowsAffected
		if rowsAffected == 0 {
			return nil
		}

		// The leveraged authorization backing these links is gone — treat as "lapsed"
		// (BCH-1341): drift every active leverage link that referenced it, independent of
		// any offering version/status.
		var links []relational.SSPLeverageLink
		if err := tx.Where("leveraged_auth_uuid = ? AND status = ?", authID, relational.SSPLeverageStatusActive).Find(&links).Error; err != nil {
			return fmt.Errorf("failed to load leverage links for lapsed authorization: %w", err)
		}
		for i := range links {
			info, ok, err := applyDriftToLink(tx, &links[i], "leveraged authorization revoked")
			if err != nil {
				return err
			}
			if ok {
				driftedLinks = append(driftedLinks, info)
			}
		}
		return nil
	}); err != nil {
		h.sugar.Errorf("Failed to delete leveraged authorization: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	enqueueLeverageDriftNotificationsAsync(ctx, h.sugar, h.jobEnqueuer, driftedLinks)

	if rowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("leveraged authorization not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UpdateControlImplementation godoc
//
//	@Summary		Update Control Implementation
//	@Description	Updates the Control Implementation for a given System Security Plan.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string									true	"System Security Plan ID"
//	@Param			control-implementation	body		oscalTypes_1_1_3.ControlImplementation	true	"Updated Control Implementation object"
//	@Success		200						{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]
//	@Failure		400						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation [put]
func (h *SystemSecurityPlanHandler) UpdateControlImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid system security plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalCI oscalTypes_1_1_3.ControlImplementation
	if err := ctx.Bind(&oscalCI); err != nil {
		h.sugar.Warnw("Invalid update control implementation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load system security plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	ci := &relational.ControlImplementation{}
	ci.UnmarshalOscal(oscalCI)
	ci.SystemSecurityPlanId = *ssp.ID
	ci.ID = ssp.ControlImplementation.ID

	if err := h.db.Model(&ci).Omit("ImplementedRequirements").Updates(&ci).Error; err != nil {
		h.sugar.Errorf("Failed to update control implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementation]{Data: *ci.MarshalOscal()})
}

// GetImplementedRequirements godoc
//
//	@Summary		Get implemented requirements for a SSP
//	@Description	Retrieves all implemented requirements for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirement]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirements(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").Preload("Profiles").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load SSP", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Resolve control IDs from all bound profiles
	controlIDs, err := h.getControlIDsForAllProfiles(ssp.Profiles)
	if err != nil {
		h.sugar.Errorw("failed to resolve control IDs for profiles", "sspID", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var implementedRequirements []relational.ImplementedRequirement
	query := h.db.Where("control_implementation_id = ?", ssp.ControlImplementation.ID)
	if len(controlIDs) > 0 {
		// controlIDs carry canonical casing; lower them for the IN match.
		query = query.Where("LOWER(control_id) IN ?", normalizeControlIDs(controlIDs))
	}

	if err := query.Find(&implementedRequirements).Error; err != nil {
		h.sugar.Errorw("failed to get implemented requirements", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalReqs := make([]oscalTypes_1_1_3.ImplementedRequirement, len(implementedRequirements))
	for i, req := range implementedRequirements {
		oscalReqs[i] = *req.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirement]{Data: oscalReqs})
}

// CreateImplementedRequirement godoc
//
//	@Summary		Create a new implemented requirement for a SSP
//	@Description	Creates a new implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string									true	"SSP ID"
//	@Param			requirement	body		oscalTypes_1_1_3.ImplementedRequirement	true	"Implemented Requirement data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalReq oscalTypes_1_1_3.ImplementedRequirement
	if err := ctx.Bind(&oscalReq); err != nil {
		h.sugar.Warnw("Invalid create implemented requirement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.validateImplementedRequirementInput(&oscalReq); err != nil {
		h.sugar.Warnw("Invalid implemented requirement input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relReq := &relational.ImplementedRequirement{}
	relReq.UnmarshalOscal(oscalReq)
	relReq.ControlImplementationId = *ssp.ControlImplementation.ID
	// Store the catalog-canonical casing regardless of what the client supplied.
	relReq.ControlId = h.canonicalizeControlID(id, relReq.ControlId)

	if err := h.db.Create(relReq).Error; err != nil {
		h.sugar.Errorf("Failed to create implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]{Data: *relReq.MarshalOscal()})
}

// UpdateImplementedRequirement godoc
//
//	@Summary		Update an implemented requirement for a SSP
//	@Description	Updates an existing implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string									true	"SSP ID"
//	@Param			reqId		path		string									true	"Requirement ID"
//	@Param			requirement	body		oscalTypes_1_1_3.ImplementedRequirement	true	"Implemented Requirement data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingReq relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).First(&existingReq).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalReq oscalTypes_1_1_3.ImplementedRequirement
	if err := ctx.Bind(&oscalReq); err != nil {
		h.sugar.Warnw("Invalid update implemented requirement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relReq := &relational.ImplementedRequirement{}
	relReq.UnmarshalOscal(oscalReq)
	relReq.ControlImplementationId = *ssp.ControlImplementation.ID
	relReq.ID = &reqID
	// Store the catalog-canonical casing regardless of what the client supplied.
	relReq.ControlId = h.canonicalizeControlID(sspID, relReq.ControlId)

	if err := h.db.Save(relReq).Error; err != nil {
		h.sugar.Errorf("Failed to update implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]{Data: *relReq.MarshalOscal()})
}

// UpdateImplementedRequirementByComponent godoc
//
//	@Summary		Update a by-component within an implemented requirement
//	@Description	Deprecated: requirement-anchored by-components are legacy — the statement is
//	@Description	the canonical anchor for shared responsibility. Use
//	@Description	PUT .../statements/{stmtId}/by-components/{byComponentId} instead. This route
//	@Description	remains so existing requirement-anchored rows can be edited and wound down;
//	@Description	there is no requirement-level POST.
//	@Description
//	@Description	Updates metadata only — description, props, links, set-parameters, remarks,
//	@Description	implementation-status and responsible-roles. Any export, inherited or
//	@Description	satisfied entries in the body are IGNORED (they have their own sub-resource
//	@Description	routes); component-uuid is immutable. Previously this blind-Saved a struct
//	@Description	rebuilt from the request body, which zeroed every omitted field and upserted
//	@Description	nested associations with no cascade cleanup.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string							true	"SSP ID"
//	@Param			reqId			path		string							true	"Requirement ID"
//	@Param			byComponentId	path		string							true	"By-Component ID"
//	@Param			by-component	body		oscalTypes_1_1_3.ByComponent	true	"By-Component data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementByComponent(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentMetadata(ctx, bc)
}

// DeleteImplementedRequirement godoc
//
//	@Summary		Delete an implemented requirement from a SSP
//	@Description	Deletes an existing implemented requirement for a given SSP.
//	@Description
//	@Description	Cascades through every by-component beneath the requirement, so it returns 409
//	@Description	if any inherited entry under it is owned by a leverage subscription.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			reqId	path	string	true	"Requirement ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var req relational.ImplementedRequirement
	if err := h.db.
		Preload("ResponsibleRoles.Parties").
		Preload("ByComponents").
		Preload("Statements.ResponsibleRoles.Parties").
		Preload("Statements.ByComponents").
		Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).
		First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("implemented requirement not found")))
		}
		h.sugar.Errorf("Failed to find implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		for _, bc := range req.ByComponents {
			if err := deleteByComponentCascade(tx, *bc.ID); err != nil {
				return err
			}
		}
		for _, stmt := range req.Statements {
			for _, bc := range stmt.ByComponents {
				if err := deleteByComponentCascade(tx, *bc.ID); err != nil {
					return err
				}
			}
			if err := deleteResponsibleRoles(tx, stmt.ResponsibleRoles); err != nil {
				return err
			}
		}
		if err := deleteResponsibleRoles(tx, req.ResponsibleRoles); err != nil {
			return err
		}
		if err := tx.Where("implemented_requirement_id = ?", req.ID).Delete(&relational.Statement{}).Error; err != nil {
			return err
		}
		return tx.Delete(&req).Error
	}); err != nil {
		// Deleting a requirement cascades through every by-component beneath it, so it inherits
		// the same subscription guard: it cannot be used as a back door around the 409.
		if errors.Is(err, errInheritedOwnedBySubscription) {
			return ctx.JSON(http.StatusConflict, api.NewError(err))
		}
		h.sugar.Errorf("Failed to delete implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateImplementedRequirementStatement godoc
//
//	@Summary		Create a new statement within an implemented requirement
//	@Description	Creates a new statement within an implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			reqId		path		string						true	"Requirement ID"
//	@Param			statement	body		oscalTypes_1_1_3.Statement	true	"Statement data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Statement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingReq relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).First(&existingReq).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalStmt oscalTypes_1_1_3.Statement
	if err := ctx.Bind(&oscalStmt); err != nil {
		h.sugar.Warnw("Invalid create statement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relStmt := &relational.Statement{}
	relStmt.UnmarshalOscal(oscalStmt)
	relStmt.ImplementedRequirementId = reqID

	if err := h.db.Create(relStmt).Error; err != nil {
		h.sugar.Errorf("Failed to create statement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Statement]{Data: *relStmt.MarshalOscal()})
}

// GetBackMatter godoc
//
//	@Summary		Get SSP back-matter
//	@Description	Retrieves back-matter for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter [get]
func (h *SystemSecurityPlanHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	if ssp.BackMatter == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no back-matter for SSP %s", idParam)))
	}

	if len(ssp.BackMatter.Resources) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("no back-matter for SSP %s", idParam)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *ssp.BackMatter.MarshalOscal()})
}

// UpdateBackMatter godoc
//
//	@Summary		Update SSP back-matter
//	@Description	Updates back-matter for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			back-matter	body		oscalTypes_1_1_3.BackMatter	true	"Back Matter data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter [put]
func (h *SystemSecurityPlanHandler) UpdateBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalBackMatter oscalTypes_1_1_3.BackMatter
	if err := ctx.Bind(&oscalBackMatter); err != nil {
		h.sugar.Warnw("Invalid update back-matter request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relBackMatter := &relational.BackMatter{}
	relBackMatter.UnmarshalOscal(oscalBackMatter)
	relBackMatter.ID = ssp.BackMatter.ID
	sspIDStr := ssp.ID.String()
	parentType := "system_security_plans"
	relBackMatter.ParentID = &sspIDStr
	relBackMatter.ParentType = &parentType

	if err := h.db.Model(&relBackMatter).Omit("Resources").Updates(&relBackMatter).Error; err != nil {
		h.sugar.Errorf("Failed to update back-matter: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *relBackMatter.MarshalOscal()})
}

// GetBackMatterResources godoc
//
//	@Summary		Get back-matter resources for a SSP
//	@Description	Retrieves all back-matter resources for a given SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id	path		string	true	"SSP ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources [get]
func (h *SystemSecurityPlanHandler) GetBackMatterResources(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").Preload("BackMatter.Resources").First(&ssp, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load SSP", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalResources := make([]oscalTypes_1_1_3.Resource, len(ssp.BackMatter.Resources))
	for i, resource := range ssp.BackMatter.Resources {
		oscalResources[i] = *resource.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Resource]{Data: oscalResources})
}

// CreateBackMatterResource godoc
//
//	@Summary		Create a new back-matter resource for a SSP
//	@Description	Creates a new back-matter resource for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			resource	body		oscalTypes_1_1_3.Resource	true	"Resource data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources [post]
func (h *SystemSecurityPlanHandler) CreateBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existingSSP relational.SystemSecurityPlan
	if err := h.db.First(&existingSSP, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find SSP: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalResource oscalTypes_1_1_3.Resource
	if err := ctx.Bind(&oscalResource); err != nil {
		h.sugar.Warnw("Invalid create resource request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	relResource := &relational.BackMatterResource{}
	relResource.UnmarshalOscal(oscalResource)
	relResource.BackMatterID = *ssp.BackMatter.ID

	if err := h.db.Create(relResource).Error; err != nil {
		h.sugar.Errorf("Failed to create resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Resource]{Data: *relResource.MarshalOscal()})
}

// UpdateBackMatterResource godoc
//
//	@Summary		Update a back-matter resource for a SSP
//	@Description	Updates an existing back-matter resource for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			resourceId	path		string						true	"Resource ID"
//	@Param			resource	body		oscalTypes_1_1_3.Resource	true	"Resource data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources/{resourceId} [put]
func (h *SystemSecurityPlanHandler) UpdateBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resourceIdParam := ctx.Param("resourceId")
	resourceID, err := uuid.Parse(resourceIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid resource id", "resourceId", resourceIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingResource relational.BackMatterResource
	if err := h.db.Where("id = ? AND back_matter_id = ?", resourceID, ssp.BackMatter.ID).First(&existingResource).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalResource oscalTypes_1_1_3.Resource
	if err := ctx.Bind(&oscalResource); err != nil {
		h.sugar.Warnw("Invalid update resource request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relResource := &relational.BackMatterResource{}
	relResource.UnmarshalOscal(oscalResource)
	relResource.BackMatterID = *ssp.BackMatter.ID
	relResource.ID = resourceID

	if err := h.db.Save(relResource).Error; err != nil {
		h.sugar.Errorf("Failed to update resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Resource]{Data: *relResource.MarshalOscal()})
}

// DeleteBackMatterResource godoc
//
//	@Summary		Delete a back-matter resource from a SSP
//	@Description	Deletes an existing back-matter resource for a given SSP.
//	@Tags			System Security Plans
//	@Param			id			path	string	true	"SSP ID"
//	@Param			resourceId	path	string	true	"Resource ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/back-matter/resources/{resourceId} [delete]
func (h *SystemSecurityPlanHandler) DeleteBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resourceIdParam := ctx.Param("resourceId")
	resourceID, err := uuid.Parse(resourceIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid resource id", "resourceId", resourceIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("BackMatter").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	result := h.db.Where("id = ? AND back_matter_id = ?", resourceID, ssp.BackMatter.ID).Delete(&relational.BackMatterResource{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete resource: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("resource not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UpdateImplementedRequirementStatement godoc
//
//	@Summary		Update a statement within an implemented requirement
//	@Description	Updates an existing statement within an implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"SSP ID"
//	@Param			reqId		path		string						true	"Requirement ID"
//	@Param			stmtId		path		string						true	"Statement ID"
//	@Param			statement	body		oscalTypes_1_1_3.Statement	true	"Statement data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Statement]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatement(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stmtIdParam := ctx.Param("stmtId")
	stmtID, err := uuid.Parse(stmtIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid statement id", "stmtId", stmtIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		h.sugar.Errorw("failed to get ssp", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingReq relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).First(&existingReq).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find implemented requirement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var existingStmt relational.Statement
	if err := h.db.Where("id = ? AND implemented_requirement_id = ?", stmtID, reqID).First(&existingStmt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find statement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalStmt oscalTypes_1_1_3.Statement
	if err := ctx.Bind(&oscalStmt); err != nil {
		h.sugar.Warnw("Invalid update statement request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relStmt := &relational.Statement{}
	relStmt.UnmarshalOscal(oscalStmt)
	relStmt.ImplementedRequirementId = reqID
	relStmt.ID = &stmtID

	if err := h.db.Save(relStmt).Error; err != nil {
		h.sugar.Errorf("Failed to update statement: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Statement]{Data: *relStmt.MarshalOscal()})
}

// UpdateImplementedRequirementStatementByComponent godoc
//
//	@Summary		Update a by-component within a statement (within an implemented requirement)
//	@Description	Updates metadata only — description, props, links, set-parameters, remarks,
//	@Description	implementation-status and responsible-roles. Any export, inherited or
//	@Description	satisfied entries in the body are IGNORED: those subtrees are managed through
//	@Description	their own sub-resource routes, which enforce the leverage bookkeeping this
//	@Description	route cannot. component-uuid is immutable. Previously this blind-Saved a
//	@Description	struct rebuilt from the request body, which zeroed every omitted field and
//	@Description	upserted nested associations with no cascade cleanup.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string							true	"SSP ID"
//	@Param			reqId			path		string							true	"Requirement ID"
//	@Param			stmtId			path		string							true	"Statement ID"
//	@Param			byComponentId	path		string							true	"By-Component ID"
//	@Param			by-component	body		oscalTypes_1_1_3.ByComponent	true	"By-Component data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatementByComponent(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentMetadata(ctx, bc)
}

// updateByComponentMetadata updates an already-resolved by-component's own scalar and
// metadata fields, leaving its Export/Inherited/Satisfied subtrees strictly alone.
//
// Both by-component PUTs used to `db.Save()` a ByComponent freshly built by UnmarshalOscal
// from the request body. That had two failure modes: any field the client omitted was zeroed
// (a PUT sending only a new description silently wiped remarks, props, links, set-parameters
// and implementation-status), and any nested export/inherited/satisfied in the body was
// upserted as a GORM association with no cascade cleanup — diverging from the careful
// deleteByComponentCascade path the DELETE routes use, and bypassing the leverage bookkeeping
// (409-on-subscription-owned-inherited, satisfaction re-derivation) the sub-resource routes
// enforce. So: only the fields this route owns are written, and nested subtrees in the body
// are ignored rather than half-applied.
//
// The omitted-field half is merge semantics, and it has to be driven by the raw body: a decoded
// struct cannot distinguish "absent" from "present and empty", and GORM's map-form Updates writes
// every key it is given unconditionally (the zero-value skipping people expect applies only to
// struct-form Updates). So the update map is built from the keys the client actually sent.
func (h *SystemSecurityPlanHandler) updateByComponentMetadata(ctx echo.Context, bc *relational.ByComponent) error {
	// Read the body before Bind consumes it, then hand it back for binding.
	rawBody, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	ctx.Request().Body = io.NopCloser(bytes.NewReader(rawBody))

	present := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(rawBody)) > 0 {
		if err := json.Unmarshal(rawBody, &present); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
	}

	var oscalBC oscalTypes_1_1_3.ByComponent
	if err := ctx.Bind(&oscalBC); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// UnmarshalOscal MustParses both uuids; a body missing (or malformed in) either would
	// panic rather than 400. Echoing the path-resolved by-component's own id keeps the parse
	// total without making uuid a required body field.
	oscalBC.UUID = bc.ID.String()

	// component-uuid is immutable, so a body naming a *different* one is rejected rather than
	// silently ignored — the same treatment provided-uuid and responsibility-uuid get on the
	// inherited/satisfied PUTs. Omitting it stays legal: it defaults to the stored value.
	if trimmed := strings.TrimSpace(oscalBC.ComponentUuid); trimmed == "" {
		oscalBC.ComponentUuid = bc.ComponentUUID.String()
	} else {
		componentUUID, err := uuid.Parse(trimmed)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("component-uuid must be a valid UUID")))
		}
		if componentUUID != bc.ComponentUUID {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf(
				"component-uuid is immutable: it identifies which component this by-component describes, and the offering-item coherence check joins on it")))
		}
	}

	parsed := &relational.ByComponent{}
	parsed.UnmarshalOscal(oscalBC)

	if err := validateByComponentImplementationStatus(parsed); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Only the fields the body actually carried. An omitted key is left as stored; sending an
	// explicit null/empty value still clears it, which is how a client asks for that.
	updates := map[string]any{}
	if _, ok := present["description"]; ok {
		updates["description"] = parsed.Description
	}
	if _, ok := present["remarks"]; ok {
		updates["remarks"] = parsed.Remarks
	}
	if _, ok := present["props"]; ok {
		updates["props"] = parsed.Props
	}
	if _, ok := present["links"]; ok {
		updates["links"] = parsed.Links
	}
	if _, ok := present["set-parameters"]; ok {
		updates["set_parameters"] = parsed.SetParameters
	}
	if _, ok := present["implementation-status"]; ok {
		updates["implementation_status"] = parsed.ImplementationStatus
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if len(updates) > 0 {
			if err := tx.Model(&relational.ByComponent{}).
				Where("id = ?", bc.ID).
				Updates(updates).Error; err != nil {
				return err
			}
		}
		// responsible-roles stays REPLACE, not merge: an omitted roles list clears the stored
		// roles. That is deliberate and pinned by TestUpdateByComponentReplacesResponsibleRoles —
		// it is a collection this route owns outright, unlike the scalars above.
		return replaceResponsibleRoles(tx, bc, *bc.ID, parsed.ResponsibleRoles)
	}); err != nil {
		h.sugar.Errorf("Failed to update by-component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	updated, err := h.reloadByComponent(*bc.ID)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK,
		handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]{Data: *updated.MarshalOscal()},
	)
}

// replaceResponsibleRoles swaps a parent's polymorphic ResponsibleRoles for a new set.
//
// The old rows go through deleteResponsibleRoles, so their responsible_role_parties join rows
// are cleared before the roles are deleted (the Party records themselves are shared and must
// survive). The new rows are written with tx.Create and an explicitly-set parent_id/parent_type
// — NOT through Association("ResponsibleRoles").Append, which writes the role rows but does not
// cascade into each role's own Parties many2many, silently leaving every responsible_role_parties
// join row unwritten. Create does cascade; it is the same path the nested by-component create
// already relies on.
func replaceResponsibleRoles(tx *gorm.DB, parent any, parentID uuid.UUID, roles []relational.ResponsibleRole) error {
	// A polymorphic parent_type is filled with the owner's table name. Derive it from the parsed
	// schema rather than hardcoding "by_components" / "inherited_control_implementations" / ...
	// at each call site, so a table rename can't silently strand a role set.
	stmt := &gorm.Statement{DB: tx}
	if err := stmt.Parse(parent); err != nil {
		return err
	}
	parentType := stmt.Schema.Table

	var existing []relational.ResponsibleRole
	if err := tx.Where("parent_id = ? AND parent_type = ?", parentID, parentType).
		Find(&existing).Error; err != nil {
		return err
	}
	if err := deleteResponsibleRoles(tx, existing); err != nil {
		return err
	}
	if len(roles) == 0 {
		return nil
	}

	for i := range roles {
		roles[i].ID = nil
		roles[i].ParentID = &parentID
		roles[i].ParentType = parentType
	}
	// Create, not Association("ResponsibleRoles").Append: Append writes the role rows but does
	// NOT cascade into each role's own Parties many2many, silently leaving every
	// responsible_role_parties join row unwritten. A plain Create does cascade — it is the same
	// path the nested by-component create already relies on.
	return tx.Create(&roles).Error
}

// reloadByComponent re-fetches a by-component with every subtree the single-by-component GET
// contract promises: export (with provided/responsibilities and their responsible-roles),
// inherited, satisfied, and the by-component's own responsible-roles.
func (h *SystemSecurityPlanHandler) reloadByComponent(byComponentID uuid.UUID) (*relational.ByComponent, error) {
	var bc relational.ByComponent
	err := h.db.
		Preload("ResponsibleRoles.Parties").
		Preload("Inherited.ResponsibleRoles.Parties").
		Preload("Satisfied.ResponsibleRoles.Parties").
		Preload("Export.Provided.ResponsibleRoles.Parties").
		Preload("Export.Responsibilities.ResponsibleRoles.Parties").
		First(&bc, "id = ?", byComponentID).Error
	return &bc, err
}

// DeleteImplementedRequirementStatementByComponent godoc
//
//	@Summary		Delete a by-component within a statement (within an implemented requirement)
//	@Description	Deletes a by-component within an existing statement within an implemented requirement for a given SSP.
//	@Description
//	@Description	Returns 409 if any of the by-component's inherited entries is owned by a
//	@Description	leverage subscription — deleting the parent must not be a way around the same
//	@Description	guard the inherited sub-resource DELETE enforces. Unsubscribe first.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			stmtId			path		string	true	"Statement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		409				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementStatementByComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stmtIdParam := ctx.Param("stmtId")
	stmtID, err := uuid.Parse(stmtIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid statement id", "stmtId", stmtIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	byComponentIdParam := ctx.Param("byComponentId")
	byComponentID, err := uuid.Parse(byComponentIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid component id", "byComponentId", byComponentIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Step 1: Verify SSP exists
	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Step 2: Verify Implemented Requirement belongs to SSP
	var req relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).
		First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("requirement not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Step 3: Verify Statement belongs to Requirement
	var stmt relational.Statement
	if err := h.db.Where("id = ? AND implemented_requirement_id = ?", stmtID, req.ID).
		First(&stmt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("statement not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Step 4: Verify ByComponent belongs to Statement
	var existing relational.ByComponent
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?",
		byComponentID, stmt.ID, "statements").
		First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("by-component not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		return deleteByComponentCascade(tx, *existing.ID)
	}); err != nil {
		if errors.Is(err, errInheritedOwnedBySubscription) {
			return ctx.JSON(http.StatusConflict, api.NewError(err))
		}
		h.sugar.Errorf("Failed to delete by-component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.NoContent(http.StatusNoContent)
}

// CreateImplementedRequirementStatementByComponent godoc
//
//	@Summary		Create a by-component within a statement (within an implemented requirement)
//	@Description	Create a by-component within an existing statement within an implemented requirement for a given SSP.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string							true	"SSP ID"
//	@Param			reqId			path		string							true	"Requirement ID"
//	@Param			stmtId			path		string							true	"Statement ID"
//	@Param			by-component	body		oscalTypes_1_1_3.ByComponent	true	"By-Component data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatementByComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIdParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid requirement id", "reqId", reqIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	stmtIdParam := ctx.Param("stmtId")
	stmtID, err := uuid.Parse(stmtIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid statement id", "stmtId", stmtIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Step 1: Verify SSP exists
	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").
		First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Step 2: Verify Implemented Requirement belongs to SSP
	var req relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).
		First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("requirement not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Step 3: Verify Statement belongs to Requirement
	var stmt relational.Statement
	if err := h.db.Where("id = ? AND implemented_requirement_id = ?", stmtID, req.ID).
		First(&stmt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("statement not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Step 5: Parse request body
	var oscalBC oscalTypes_1_1_3.ByComponent
	if err := ctx.Bind(&oscalBC); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Step 6: Map and create
	relBC := &relational.ByComponent{}
	relBC.UnmarshalOscal(oscalBC)

	if err := validateByComponentImplementationStatus(relBC); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relBC.ParentID = stmt.ID
	parentType := "statements"
	relBC.ParentType = &parentType

	if err := h.db.Create(relBC).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Step 7: Return created
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]{Data: *relBC.MarshalOscal()})
}

// resolveByComponentForRequirement parses and verifies a by-component that belongs
// directly to an implemented requirement (control-level). On any failure it writes
// the appropriate JSON error response to ctx and returns ok=false; callers should
// return nil immediately when ok is false.
func (h *SystemSecurityPlanHandler) resolveByComponentForRequirement(ctx echo.Context) (bc *relational.ByComponent, ok bool) {
	sspID, reqID, err := parseSSPReqIDs(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid by-component path params", "error", err)
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}

	byComponentIdParam := ctx.Param("byComponentId")
	byComponentID, err := uuid.Parse(byComponentIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid component id", "byComponentId", byComponentIdParam, "error", err)
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	var req relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).
		First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("requirement not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	var found relational.ByComponent
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?",
		byComponentID, req.ID, "implemented_requirements").
		First(&found).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("by-component not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	return &found, true
}

// resolveByComponentForStatement parses and verifies a by-component that belongs to
// a statement within an implemented requirement (statement-level). Same contract as
// resolveByComponentForRequirement.
func (h *SystemSecurityPlanHandler) resolveByComponentForStatement(ctx echo.Context) (bc *relational.ByComponent, ok bool) {
	sspID, reqID, stmtID, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid by-component path params", "error", err)
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}

	byComponentIdParam := ctx.Param("byComponentId")
	byComponentID, err := uuid.Parse(byComponentIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid component id", "byComponentId", byComponentIdParam, "error", err)
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return nil, false
	}

	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation").First(&ssp, "id = ?", sspID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	var req relational.ImplementedRequirement
	if err := h.db.Where("id = ? AND control_implementation_id = ?", reqID, ssp.ControlImplementation.ID).
		First(&req).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("requirement not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	var stmt relational.Statement
	if err := h.db.Where("id = ? AND implemented_requirement_id = ?", stmtID, req.ID).
		First(&stmt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("statement not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	var found relational.ByComponent
	if err := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?",
		byComponentID, stmt.ID, "statements").
		First(&found).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("by-component not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}

	return &found, true
}

// reloadByComponentExport re-fetches a by-component's Export with its nested Provided
// and Responsibilities (and their responsible roles) fully preloaded, for use in
// responses after a create/update.
func (h *SystemSecurityPlanHandler) reloadByComponentExport(byComponentID uuid.UUID) (*relational.Export, error) {
	var export relational.Export
	err := h.db.
		Preload("Provided").
		Preload("Provided.ResponsibleRoles").
		Preload("Provided.ResponsibleRoles.Parties").
		Preload("Responsibilities").
		Preload("Responsibilities.ResponsibleRoles").
		Preload("Responsibilities.ResponsibleRoles.Parties").
		Where("by_component_id = ?", byComponentID).
		First(&export).Error
	return &export, err
}

// getByComponentExport reads the Export sub-resource for an already-resolved by-component.
func (h *SystemSecurityPlanHandler) getByComponentExport(ctx echo.Context, bc *relational.ByComponent) error {
	export, err := h.reloadByComponentExport(*bc.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Export]{Data: *export.MarshalOscal()})
}

// createByComponentExport creates the (singleton) Export sub-resource for an
// already-resolved by-component. A by-component may have at most one Export.
func (h *SystemSecurityPlanHandler) createByComponentExport(ctx echo.Context, bc *relational.ByComponent) error {
	var oscalExport oscalTypes_1_1_3.Export
	if err := ctx.Bind(&oscalExport); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relExport := &relational.Export{}
	relExport.UnmarshalOscal(oscalExport)
	relExport.ByComponentId = *bc.ID

	conflict := false
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		// Export.ByComponentId has no unique DB constraint (this ticket makes no
		// schema change), so an advisory lock keyed on the by-component closes the
		// race between the existence check and the insert for concurrent creates.
		if err := lockByComponentSubtreeWrite(tx, *bc.ID); err != nil {
			return err
		}

		var existing relational.Export
		err := tx.Where("by_component_id = ?", bc.ID).First(&existing).Error
		if err == nil {
			conflict = true
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		return tx.Create(relExport).Error
	}); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if conflict {
		return ctx.JSON(http.StatusConflict, api.NewError(fmt.Errorf("export already exists for this by-component")))
	}

	created, err := h.reloadByComponentExport(*bc.ID)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Export]{Data: *created.MarshalOscal()})
}

// lockByComponentSubtreeWrite serializes concurrent WRITES to one by-component's subtree — its
// singleton Export, and its Inherited/Satisfied entries — with a transaction-scoped Postgres
// advisory lock keyed on the by-component's UUID.
//
// EVERY writer that performs a read-modify-write over that subtree must take it, not just the
// creates. Nothing in the schema enforces exports.by_component_id uniqueness, and four writers
// re-derive SSPLeverageLink.Satisfaction from a satisfied set they read earlier in the same
// transaction: the satisfied CREATE, the satisfied DELETE, Subscribe (via
// resyncLeverageSatisfaction), and ReAttest. Each computes the SET value in Go from a snapshot, so
// any writer that skips the lock can overwrite a concurrent writer's freshly-derived value with a
// stale one — a plain lost update. Partial adoption is worse than useless: it serializes only the
// writers that opted in, while reading as though the subtree were safe.
//
// ReAttest's `WHERE status = drifted` guard is not a substitute — it defends against a concurrent
// re-attest, not against a concurrent satisfied write, which never touches status.
//
// Three of those four writers reach the derivation through resyncLeverageSatisfaction, which now
// takes this lock ITSELF — so the invariant is enforced by construction on that path rather than by
// everyone remembering. (It was half-missed twice: first the satisfied DELETE, then Subscribe.)
// Callers still take it explicitly and earlier, to cover their own inserts/deletes as well as the
// derivation; advisory locks are re-entrant within a transaction, so the double take is free.
// ReAttest derives inline rather than via resync, so its lock is genuinely load-bearing.
//
// The cached Satisfaction is what the drift detector and the notification path read, which is the
// whole reason resyncLeverageSatisfaction exists.
//
// (Named "...Create" until a delete needed it too — that create-only name is exactly why the
// delete and ReAttest were missed. It is a subtree-WRITE lock; keep the name honest.)
//
// The lock key string stays "export-create:" despite the wider scope: it is only meaningful as a
// value all writers agree on, and changing it would stop old and new pods serializing against
// each other during a rolling deploy.
//
// It is a no-op against non-Postgres test drivers.
func lockByComponentSubtreeWrite(tx *gorm.DB, byComponentID uuid.UUID) error {
	if tx.Name() != "postgres" {
		return nil
	}
	sum := sha256.Sum256([]byte("export-create:" + byComponentID.String()))
	key1 := int32(binary.BigEndian.Uint32(sum[0:4]))
	key2 := int32(binary.BigEndian.Uint32(sum[4:8]))
	return tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", key1, key2).Error
}

// updateByComponentExport updates the scalar fields (description, remarks, props,
// links) of an existing Export. The Provided and Responsibilities entries are managed
// individually via their own routes and are left untouched here.
func (h *SystemSecurityPlanHandler) updateByComponentExport(ctx echo.Context, bc *relational.ByComponent) error {
	var existing relational.Export
	if err := h.db.Where("by_component_id = ?", bc.ID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalExport oscalTypes_1_1_3.Export
	if err := ctx.Bind(&oscalExport); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if oscalExport.Provided != nil && len(*oscalExport.Provided) > 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("provided entries must be managed via the export/provided routes, not by updating the export directly")))
	}
	if oscalExport.Responsibilities != nil && len(*oscalExport.Responsibilities) > 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("responsibility entries must be managed via the export/responsibilities routes, not by updating the export directly")))
	}

	parsed := &relational.Export{}
	parsed.UnmarshalOscal(oscalExport)

	existing.Description = parsed.Description
	existing.Remarks = parsed.Remarks
	existing.Props = parsed.Props
	existing.Links = parsed.Links

	if err := h.db.Save(&existing).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	updated, err := h.reloadByComponentExport(*bc.ID)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Export]{Data: *updated.MarshalOscal()})
}

// deleteByComponentExport deletes an existing Export and its nested Provided and
// Responsibilities entries, including their ResponsibleRoles and responsible_role_parties
// join rows. Children are deleted explicitly rather than relying on a DB-level cascade,
// since this ticket makes no schema change.
func (h *SystemSecurityPlanHandler) deleteByComponentExport(ctx echo.Context, bc *relational.ByComponent) error {
	var existing relational.Export
	if err := h.db.
		Preload("Provided.ResponsibleRoles.Parties").
		Preload("Responsibilities.ResponsibleRoles.Parties").
		Where("by_component_id = ?", bc.ID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		return deleteExportCascade(tx, &existing)
	}); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// deleteExportCascade deletes an Export's nested Provided and Responsibilities
// entries (and their ResponsibleRoles/parties), then the Export itself. Shared
// by deleteByComponentExport and deleteByComponentCascade so the two paths
// can't drift apart. export.Provided and export.Responsibilities (with their
// ResponsibleRoles.Parties) must already be preloaded by the caller.
func deleteExportCascade(tx *gorm.DB, export *relational.Export) error {
	for _, provided := range export.Provided {
		if err := deleteResponsibleRoles(tx, provided.ResponsibleRoles); err != nil {
			return err
		}
	}
	for _, resp := range export.Responsibilities {
		if err := deleteResponsibleRoles(tx, resp.ResponsibleRoles); err != nil {
			return err
		}
	}
	if err := tx.Where("export_id = ?", export.ID).Delete(&relational.ProvidedControlImplementation{}).Error; err != nil {
		return err
	}
	if err := tx.Where("export_id = ?", export.ID).Delete(&relational.ControlImplementationResponsibility{}).Error; err != nil {
		return err
	}
	return tx.Delete(export).Error
}

// deleteResponsibleRoles removes the given ResponsibleRoles along with their
// many2many Party join rows. The join rows are cleared explicitly first since
// deleting a ResponsibleRole directly would leave its responsible_role_parties
// rows behind (Party records themselves are shared and must not be deleted).
func deleteResponsibleRoles(tx *gorm.DB, roles []relational.ResponsibleRole) error {
	for i := range roles {
		role := &roles[i]
		if err := tx.Model(role).Association("Parties").Clear(); err != nil {
			return err
		}
		if err := tx.Delete(role).Error; err != nil {
			return err
		}
	}
	return nil
}

// deleteByComponentCascade deletes a ByComponent and every record that hangs off
// it: its own ResponsibleRoles, its Inherited and Satisfied entries (each with
// their own ResponsibleRoles), and its Export with nested Provided and
// Responsibilities entries (each with their own ResponsibleRoles). None of this
// cascades at the DB level, so it is deleted explicitly, leaves-first, inside
// the caller's transaction.
func deleteByComponentCascade(tx *gorm.DB, byComponentID uuid.UUID) error {
	// Taken before the preload, so the set this function reads is the set it deletes. Without it
	// the guard below is a pre-check against a snapshot while the deletes take a fresh one: a
	// Subscribe committing in between would have its inherited row destroyed and its link left
	// dangling, which is the exact invariant the guard exists to hold. Subscribe takes this same
	// lock, so the two serialize; advisory locks are re-entrant within a transaction, so callers
	// already holding it pay nothing.
	if err := lockByComponentSubtreeWrite(tx, byComponentID); err != nil {
		return err
	}

	var bc relational.ByComponent
	if err := tx.
		Preload("ResponsibleRoles.Parties").
		Preload("Inherited.ResponsibleRoles.Parties").
		Preload("Satisfied.ResponsibleRoles.Parties").
		Preload("Export.Provided.ResponsibleRoles.Parties").
		Preload("Export.Responsibilities.ResponsibleRoles.Parties").
		First(&bc, "id = ?", byComponentID).Error; err != nil {
		return err
	}

	// An SSPLeverageLink must never be left pointing at nothing: the drift detector and the
	// notification path both read through link.InheritedUUID, and InheritedUUID is a bare value
	// with no FK, so nothing at the DB level stops the row vanishing underneath it.
	//
	// The guard lives HERE rather than in the inherited sub-resource DELETE alone, because every
	// path that destroys a by-component destroys its Inherited rows with it — the statement-level
	// and requirement-level by-component DELETEs, and the requirement DELETE that cascades through
	// them. Guarding only the sub-resource route left the invariant trivially bypassable by
	// deleting the parent instead. Callers map this to 409, same as the sub-resource route.
	inheritedIDs := make([]uuid.UUID, 0, len(bc.Inherited))
	for i := range bc.Inherited {
		inheritedIDs = append(inheritedIDs, *bc.Inherited[i].ID)
	}
	if err := assertInheritedNotSubscribed(tx, inheritedIDs); err != nil {
		return err
	}

	if err := deleteResponsibleRoles(tx, bc.ResponsibleRoles); err != nil {
		return err
	}

	// Deletes are scoped to the ids checked above rather than to by_component_id, so the rows
	// destroyed are exactly the rows guarded — and exactly the rows whose responsible_roles were
	// cleaned up. A bulk delete would take a fresh snapshot, orphaning the roles of any row that
	// appeared after the preload.
	for _, inherited := range bc.Inherited {
		if err := deleteResponsibleRoles(tx, inherited.ResponsibleRoles); err != nil {
			return err
		}
	}
	if len(inheritedIDs) > 0 {
		if err := tx.Where("id IN ?", inheritedIDs).Delete(&relational.InheritedControlImplementation{}).Error; err != nil {
			return err
		}
	}

	satisfiedIDs := make([]uuid.UUID, 0, len(bc.Satisfied))
	for i := range bc.Satisfied {
		satisfiedIDs = append(satisfiedIDs, *bc.Satisfied[i].ID)
	}
	for _, satisfied := range bc.Satisfied {
		if err := deleteResponsibleRoles(tx, satisfied.ResponsibleRoles); err != nil {
			return err
		}
	}
	if len(satisfiedIDs) > 0 {
		if err := tx.Where("id IN ?", satisfiedIDs).Delete(&relational.SatisfiedControlImplementationResponsibility{}).Error; err != nil {
			return err
		}
	}

	if bc.Export != nil {
		if err := deleteExportCascade(tx, bc.Export); err != nil {
			return err
		}
	}

	return tx.Delete(&bc).Error
}

// GetImplementedRequirementByComponentExport godoc
//
//	@Summary		Get the export for a control-level by-component
//	@Description	Retrieves the Export (with nested Provided and Responsibilities) for a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Export]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponentExport(ctx, bc)
}

// CreateImplementedRequirementByComponentExport godoc
//
//	@Summary		Create the export for a control-level by-component
//	@Description	Creates the Export for a by-component within an implemented requirement. A by-component may have at most one Export.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string					true	"SSP ID"
//	@Param			reqId			path		string					true	"Requirement ID"
//	@Param			byComponentId	path		string					true	"By-Component ID"
//	@Param			export			body		oscalTypes_1_1_3.Export	true	"Export data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Export]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		409				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.createByComponentExport(ctx, bc)
}

// UpdateImplementedRequirementByComponentExport godoc
//
//	@Summary		Update the export for a control-level by-component
//	@Description	Updates the scalar fields of an existing Export for a by-component within an implemented requirement. Provided and Responsibilities entries are managed via their own routes.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string					true	"SSP ID"
//	@Param			reqId			path		string					true	"Requirement ID"
//	@Param			byComponentId	path		string					true	"By-Component ID"
//	@Param			export			body		oscalTypes_1_1_3.Export	true	"Export data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Export]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentExport(ctx, bc)
}

// DeleteImplementedRequirementByComponentExport godoc
//
//	@Summary		Delete the export for a control-level by-component
//	@Description	Deletes the Export (and its Provided/Responsibilities entries) for a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Param			id				path	string	true	"SSP ID"
//	@Param			reqId			path	string	true	"Requirement ID"
//	@Param			byComponentId	path	string	true	"By-Component ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.deleteByComponentExport(ctx, bc)
}

// GetImplementedRequirementStatementByComponentExport godoc
//
//	@Summary		Get the export for a statement-level by-component
//	@Description	Retrieves the Export (with nested Provided and Responsibilities) for a by-component within a statement.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id				path		string	true	"SSP ID"
//	@Param			reqId			path		string	true	"Requirement ID"
//	@Param			stmtId			path		string	true	"Statement ID"
//	@Param			byComponentId	path		string	true	"By-Component ID"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Export]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export [get]
func (h *SystemSecurityPlanHandler) GetImplementedRequirementStatementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.getByComponentExport(ctx, bc)
}

// CreateImplementedRequirementStatementByComponentExport godoc
//
//	@Summary		Create the export for a statement-level by-component
//	@Description	Creates the Export for a by-component within a statement. A by-component may have at most one Export.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string					true	"SSP ID"
//	@Param			reqId			path		string					true	"Requirement ID"
//	@Param			stmtId			path		string					true	"Statement ID"
//	@Param			byComponentId	path		string					true	"By-Component ID"
//	@Param			export			body		oscalTypes_1_1_3.Export	true	"Export data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Export]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		409				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.createByComponentExport(ctx, bc)
}

// UpdateImplementedRequirementStatementByComponentExport godoc
//
//	@Summary		Update the export for a statement-level by-component
//	@Description	Updates the scalar fields of an existing Export for a by-component within a statement. Provided and Responsibilities entries are managed via their own routes.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string					true	"SSP ID"
//	@Param			reqId			path		string					true	"Requirement ID"
//	@Param			stmtId			path		string					true	"Statement ID"
//	@Param			byComponentId	path		string					true	"By-Component ID"
//	@Param			export			body		oscalTypes_1_1_3.Export	true	"Export data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Export]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentExport(ctx, bc)
}

// DeleteImplementedRequirementStatementByComponentExport godoc
//
//	@Summary		Delete the export for a statement-level by-component
//	@Description	Deletes the Export (and its Provided/Responsibilities entries) for a by-component within a statement.
//	@Tags			System Security Plans
//	@Param			id				path	string	true	"SSP ID"
//	@Param			reqId			path	string	true	"Requirement ID"
//	@Param			stmtId			path	string	true	"Statement ID"
//	@Param			byComponentId	path	string	true	"By-Component ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementStatementByComponentExport(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.deleteByComponentExport(ctx, bc)
}

// findExportForByComponent looks up the (singleton) Export belonging to an
// already-resolved by-component, writing a 404 if none exists.
func (h *SystemSecurityPlanHandler) findExportForByComponent(ctx echo.Context, bc *relational.ByComponent) (*relational.Export, bool) {
	var export relational.Export
	if err := h.db.Where("by_component_id = ?", bc.ID).First(&export).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("export not found")))
			return nil, false
		}
		_ = ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		return nil, false
	}
	return &export, true
}

// createByComponentExportProvided creates a Provided entry under an already-resolved
// by-component's Export.
func (h *SystemSecurityPlanHandler) createByComponentExportProvided(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	var oscalProvided oscalTypes_1_1_3.ProvidedControlImplementation
	if err := ctx.Bind(&oscalProvided); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relProvided := &relational.ProvidedControlImplementation{}
	relProvided.UnmarshalOscal(oscalProvided)
	relProvided.ExportId = *export.ID

	if err := h.db.Create(relProvided).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.ProvidedControlImplementation]{Data: *relProvided.MarshalOscal()})
}

// updateByComponentExportProvided replaces an existing Provided entry under an
// already-resolved by-component's Export.
func (h *SystemSecurityPlanHandler) updateByComponentExportProvided(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	providedIdParam := ctx.Param("providedId")
	providedID, err := uuid.Parse(providedIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid provided id", "providedId", providedIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existing relational.ProvidedControlImplementation
	if err := h.db.Where("id = ? AND export_id = ?", providedID, export.ID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("provided entry not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalProvided oscalTypes_1_1_3.ProvidedControlImplementation
	if err := ctx.Bind(&oscalProvided); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relProvided := &relational.ProvidedControlImplementation{}
	relProvided.UnmarshalOscal(oscalProvided)
	relProvided.ID = &providedID
	relProvided.ExportId = *export.ID

	if err := h.db.Save(relProvided).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ProvidedControlImplementation]{Data: *relProvided.MarshalOscal()})
}

// deleteByComponentExportProvided deletes an existing Provided entry under an
// already-resolved by-component's Export.
func (h *SystemSecurityPlanHandler) deleteByComponentExportProvided(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	providedIdParam := ctx.Param("providedId")
	providedID, err := uuid.Parse(providedIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid provided id", "providedId", providedIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	result := h.db.Where("id = ? AND export_id = ?", providedID, export.ID).Delete(&relational.ProvidedControlImplementation{})
	if result.Error != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("provided entry not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateImplementedRequirementByComponentExportProvided godoc
//
//	@Summary		Create a provided entry on a control-level by-component's export
//	@Description	Creates a ProvidedControlImplementation entry under the Export of a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string											true	"SSP ID"
//	@Param			reqId			path		string											true	"Requirement ID"
//	@Param			byComponentId	path		string											true	"By-Component ID"
//	@Param			provided		body		oscalTypes_1_1_3.ProvidedControlImplementation	true	"Provided data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ProvidedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/provided [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.createByComponentExportProvided(ctx, bc)
}

// UpdateImplementedRequirementByComponentExportProvided godoc
//
//	@Summary		Update a provided entry on a control-level by-component's export
//	@Description	Replaces an existing ProvidedControlImplementation entry under the Export of a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string											true	"SSP ID"
//	@Param			reqId			path		string											true	"Requirement ID"
//	@Param			byComponentId	path		string											true	"By-Component ID"
//	@Param			providedId		path		string											true	"Provided entry ID"
//	@Param			provided		body		oscalTypes_1_1_3.ProvidedControlImplementation	true	"Provided data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ProvidedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/provided/{providedId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentExportProvided(ctx, bc)
}

// DeleteImplementedRequirementByComponentExportProvided godoc
//
//	@Summary		Delete a provided entry on a control-level by-component's export
//	@Description	Deletes an existing ProvidedControlImplementation entry under the Export of a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Param			id				path	string	true	"SSP ID"
//	@Param			reqId			path	string	true	"Requirement ID"
//	@Param			byComponentId	path	string	true	"By-Component ID"
//	@Param			providedId		path	string	true	"Provided entry ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/provided/{providedId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.deleteByComponentExportProvided(ctx, bc)
}

// CreateImplementedRequirementStatementByComponentExportProvided godoc
//
//	@Summary		Create a provided entry on a statement-level by-component's export
//	@Description	Creates a ProvidedControlImplementation entry under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string											true	"SSP ID"
//	@Param			reqId			path		string											true	"Requirement ID"
//	@Param			stmtId			path		string											true	"Statement ID"
//	@Param			byComponentId	path		string											true	"By-Component ID"
//	@Param			provided		body		oscalTypes_1_1_3.ProvidedControlImplementation	true	"Provided data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ProvidedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/provided [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.createByComponentExportProvided(ctx, bc)
}

// UpdateImplementedRequirementStatementByComponentExportProvided godoc
//
//	@Summary		Update a provided entry on a statement-level by-component's export
//	@Description	Replaces an existing ProvidedControlImplementation entry under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string											true	"SSP ID"
//	@Param			reqId			path		string											true	"Requirement ID"
//	@Param			stmtId			path		string											true	"Statement ID"
//	@Param			byComponentId	path		string											true	"By-Component ID"
//	@Param			providedId		path		string											true	"Provided entry ID"
//	@Param			provided		body		oscalTypes_1_1_3.ProvidedControlImplementation	true	"Provided data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ProvidedControlImplementation]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/provided/{providedId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentExportProvided(ctx, bc)
}

// DeleteImplementedRequirementStatementByComponentExportProvided godoc
//
//	@Summary		Delete a provided entry on a statement-level by-component's export
//	@Description	Deletes an existing ProvidedControlImplementation entry under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Param			id				path	string	true	"SSP ID"
//	@Param			reqId			path	string	true	"Requirement ID"
//	@Param			stmtId			path	string	true	"Statement ID"
//	@Param			byComponentId	path	string	true	"By-Component ID"
//	@Param			providedId		path	string	true	"Provided entry ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/provided/{providedId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementStatementByComponentExportProvided(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.deleteByComponentExportProvided(ctx, bc)
}

// createByComponentExportResponsibility creates a Responsibility entry under an
// already-resolved by-component's Export.
func (h *SystemSecurityPlanHandler) createByComponentExportResponsibility(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	var oscalResponsibility oscalTypes_1_1_3.ControlImplementationResponsibility
	if err := ctx.Bind(&oscalResponsibility); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relResponsibility := &relational.ControlImplementationResponsibility{}
	relResponsibility.UnmarshalOscal(oscalResponsibility)
	relResponsibility.ExportId = *export.ID

	if err := h.db.Create(relResponsibility).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]{Data: *relResponsibility.MarshalOscal()})
}

// updateByComponentExportResponsibility replaces an existing Responsibility entry
// under an already-resolved by-component's Export.
func (h *SystemSecurityPlanHandler) updateByComponentExportResponsibility(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	responsibilityIdParam := ctx.Param("responsibilityId")
	responsibilityID, err := uuid.Parse(responsibilityIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid responsibility id", "responsibilityId", responsibilityIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var existing relational.ControlImplementationResponsibility
	if err := h.db.Where("id = ? AND export_id = ?", responsibilityID, export.ID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("responsibility entry not found")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalResponsibility oscalTypes_1_1_3.ControlImplementationResponsibility
	if err := ctx.Bind(&oscalResponsibility); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relResponsibility := &relational.ControlImplementationResponsibility{}
	relResponsibility.UnmarshalOscal(oscalResponsibility)
	relResponsibility.ID = &responsibilityID
	relResponsibility.ExportId = *export.ID

	if err := h.db.Save(relResponsibility).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]{Data: *relResponsibility.MarshalOscal()})
}

// deleteByComponentExportResponsibility deletes an existing Responsibility entry
// under an already-resolved by-component's Export.
func (h *SystemSecurityPlanHandler) deleteByComponentExportResponsibility(ctx echo.Context, bc *relational.ByComponent) error {
	export, ok := h.findExportForByComponent(ctx, bc)
	if !ok {
		return nil
	}

	responsibilityIdParam := ctx.Param("responsibilityId")
	responsibilityID, err := uuid.Parse(responsibilityIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid responsibility id", "responsibilityId", responsibilityIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	result := h.db.Where("id = ? AND export_id = ?", responsibilityID, export.ID).Delete(&relational.ControlImplementationResponsibility{})
	if result.Error != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}
	if result.RowsAffected == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("responsibility entry not found")))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// CreateImplementedRequirementByComponentExportResponsibility godoc
//
//	@Summary		Create a responsibility entry on a control-level by-component's export
//	@Description	Creates a ControlImplementationResponsibility entry under the Export of a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string													true	"SSP ID"
//	@Param			reqId			path		string													true	"Requirement ID"
//	@Param			byComponentId	path		string													true	"By-Component ID"
//	@Param			responsibility	body		oscalTypes_1_1_3.ControlImplementationResponsibility	true	"Responsibility data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/responsibilities [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementByComponentExportResponsibility(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.createByComponentExportResponsibility(ctx, bc)
}

// UpdateImplementedRequirementByComponentExportResponsibility godoc
//
//	@Summary		Update a responsibility entry on a control-level by-component's export
//	@Description	Replaces an existing ControlImplementationResponsibility entry under the Export of a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id					path		string													true	"SSP ID"
//	@Param			reqId				path		string													true	"Requirement ID"
//	@Param			byComponentId		path		string													true	"By-Component ID"
//	@Param			responsibilityId	path		string													true	"Responsibility entry ID"
//	@Param			responsibility		body		oscalTypes_1_1_3.ControlImplementationResponsibility	true	"Responsibility data"
//	@Success		200					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]
//	@Failure		400					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/responsibilities/{responsibilityId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementByComponentExportResponsibility(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentExportResponsibility(ctx, bc)
}

// DeleteImplementedRequirementByComponentExportResponsibility godoc
//
//	@Summary		Delete a responsibility entry on a control-level by-component's export
//	@Description	Deletes an existing ControlImplementationResponsibility entry under the Export of a by-component within an implemented requirement.
//	@Description
//	@Description	Deprecated: requirement-anchored exports are legacy. Shared responsibility is
//	@Description	tracked per statement — use the statement-level equivalent under
//	@Description	.../statements/{stmtId}/by-components/{byComponentId}/export. This route stays so
//	@Description	existing requirement-anchored exports can be read and wound down.
//	@Tags			System Security Plans
//	@Param			id					path	string	true	"SSP ID"
//	@Param			reqId				path	string	true	"Requirement ID"
//	@Param			byComponentId		path	string	true	"By-Component ID"
//	@Param			responsibilityId	path	string	true	"Responsibility entry ID"
//	@Success		204					"No Content"
//	@Failure		400					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Deprecated
//	@Security	OAuth2Password
//	@Router		/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/by-components/{byComponentId}/export/responsibilities/{responsibilityId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementByComponentExportResponsibility(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForRequirement(ctx)
	if !ok {
		return nil
	}
	return h.deleteByComponentExportResponsibility(ctx, bc)
}

// CreateImplementedRequirementStatementByComponentExportResponsibility godoc
//
//	@Summary		Create a responsibility entry on a statement-level by-component's export
//	@Description	Creates a ControlImplementationResponsibility entry under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string													true	"SSP ID"
//	@Param			reqId			path		string													true	"Requirement ID"
//	@Param			stmtId			path		string													true	"Statement ID"
//	@Param			byComponentId	path		string													true	"By-Component ID"
//	@Param			responsibility	body		oscalTypes_1_1_3.ControlImplementationResponsibility	true	"Responsibility data"
//	@Success		201				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/responsibilities [post]
func (h *SystemSecurityPlanHandler) CreateImplementedRequirementStatementByComponentExportResponsibility(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.createByComponentExportResponsibility(ctx, bc)
}

// UpdateImplementedRequirementStatementByComponentExportResponsibility godoc
//
//	@Summary		Update a responsibility entry on a statement-level by-component's export
//	@Description	Replaces an existing ControlImplementationResponsibility entry under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Accept			json
//	@Produce		json
//	@Param			id					path		string													true	"SSP ID"
//	@Param			reqId				path		string													true	"Requirement ID"
//	@Param			stmtId				path		string													true	"Statement ID"
//	@Param			byComponentId		path		string													true	"By-Component ID"
//	@Param			responsibilityId	path		string													true	"Responsibility entry ID"
//	@Param			responsibility		body		oscalTypes_1_1_3.ControlImplementationResponsibility	true	"Responsibility data"
//	@Success		200					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]
//	@Failure		400					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/responsibilities/{responsibilityId} [put]
func (h *SystemSecurityPlanHandler) UpdateImplementedRequirementStatementByComponentExportResponsibility(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.updateByComponentExportResponsibility(ctx, bc)
}

// DeleteImplementedRequirementStatementByComponentExportResponsibility godoc
//
//	@Summary		Delete a responsibility entry on a statement-level by-component's export
//	@Description	Deletes an existing ControlImplementationResponsibility entry under the Export of a by-component within a statement.
//	@Tags			System Security Plans
//	@Param			id					path	string	true	"SSP ID"
//	@Param			reqId				path	string	true	"Requirement ID"
//	@Param			stmtId				path	string	true	"Statement ID"
//	@Param			byComponentId		path	string	true	"By-Component ID"
//	@Param			responsibilityId	path	string	true	"Responsibility entry ID"
//	@Success		204					"No Content"
//	@Failure		400					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/by-components/{byComponentId}/export/responsibilities/{responsibilityId} [delete]
func (h *SystemSecurityPlanHandler) DeleteImplementedRequirementStatementByComponentExportResponsibility(ctx echo.Context) error {
	bc, ok := h.resolveByComponentForStatement(ctx)
	if !ok {
		return nil
	}
	return h.deleteByComponentExportResponsibility(ctx, bc)
}

// extractControlIDsFromProfile resolves a profile and extracts all control IDs
func (h *SystemSecurityPlanHandler) extractControlIDsFromProfile(profile *relational.Profile) (controlIDs []string, err error) {
	if profile.ID != nil {
		if cachedControlIDs, ok := profileControlsCache.load(*profile.ID); ok {
			return cachedControlIDs, nil
		}
	}

	// Recover from panics in BuildControlCatalogForProfile
	defer func() {
		if r := recover(); r != nil {
			h.sugar.Errorw("Panic in extractControlIDsFromProfile", "panic", r)
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	h.sugar.Infow("Extracting control IDs from profile", "profileId", profile.ID, "importsCount", len(profile.Imports))

	idsMap, err := GetControlIDsMapFromProfile(profile, h.db)
	if err != nil {
		h.sugar.Errorw("Failed to get control IDs map from profile", "error", err)
		return nil, err
	}

	controlIDs = make([]string, 0, len(idsMap))
	for id := range idsMap {
		controlIDs = append(controlIDs, id)
	}
	controlIDs = dedupeControlIDs(controlIDs)

	// store skips empty results (see profileControlCache).
	if profile.ID != nil {
		profileControlsCache.store(*profile.ID, controlIDs)
	}

	h.sugar.Infow("Extracted control IDs from profile", "count", len(controlIDs))
	return controlIDs, nil
}

// SuggestComponents godoc
//
//	@Summary		Suggest system components for an implemented requirement
//	@Description	Returns DefinedComponents that implement the same control and are not yet present in the SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id		path		string	true	"SSP ID"
//	@Param			reqId	path		string	true	"Implemented Requirement ID"
//	@Success		200		{object}	handler.GenericDataListResponse[relational.SystemComponentSuggestion]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/suggest-components [post]
func (h *SystemSecurityPlanHandler) SuggestComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	reqIDParam := ctx.Param("reqId")
	reqID, err := uuid.Parse(reqIDParam)
	if err != nil {
		h.sugar.Warnw("Invalid implemented requirement id", "reqId", reqIDParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	suggestions, err := h.suggestionService.SuggestForImplementedRequirement(sspID, reqID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to get component suggestions", "sspID", sspID, "reqID", reqID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[relational.SystemComponentSuggestion]{Data: suggestions})
}

// SuggestComponentsForStatement godoc
//
//	@Summary		Suggest system components for a statement
//	@Description	Returns DefinedComponents that implement the statement's parent control and are not yet present in the SSP.
//	@Tags			System Security Plans
//	@Produce		json
//	@Param			id		path		string	true	"SSP ID"
//	@Param			reqId	path		string	true	"Implemented Requirement ID"
//	@Param			stmtId	path		string	true	"Statement ID"
//	@Success		200		{object}	handler.GenericDataListResponse[relational.SystemComponentSuggestion]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/suggest-components [post]
func (h *SystemSecurityPlanHandler) SuggestComponentsForStatement(ctx echo.Context) error {
	sspID, reqID, stmtID, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid statement suggestion path params", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	suggestions, err := h.suggestionService.SuggestForStatement(sspID, reqID, stmtID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to get statement component suggestions", "sspID", sspID, "reqID", reqID, "stmtID", stmtID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[relational.SystemComponentSuggestion]{Data: suggestions})
}

// ApplySuggestion godoc
//
//	@Summary		Apply a specific component suggestion for an implemented requirement
//	@Description	Creates or reuses a SystemComponent from the provided DefinedComponent and links it via ByComponent.
//	@Tags			System Security Plans
//	@Accept			json
//	@Param			id		path	string					true	"SSP ID"
//	@Param			reqId	path	string					true	"Implemented Requirement ID"
//	@Param			request	body	ApplySuggestionRequest	true	"Suggestion to apply"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/apply-suggestion [post]
func (h *SystemSecurityPlanHandler) ApplySuggestion(ctx echo.Context) error {
	sspID, reqID, err := parseSSPReqIDs(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid apply-suggestion path params", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var payload ApplySuggestionRequest
	if err := ctx.Bind(&payload); err != nil {
		h.sugar.Warnw("Invalid apply-suggestion request payload", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := payload.Validate(); err != nil {
		h.sugar.Warnw("Invalid apply-suggestion request payload", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.suggestionService.ApplySuggestionForImplementedRequirement(
		sspID,
		reqID,
		*payload.ComponentDefinitionID,
		*payload.DefinedComponentID,
	); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to apply component suggestions", "sspID", sspID, "reqID", reqID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// ApplySuggestionForStatement godoc
//
//	@Summary		Apply a specific component suggestion for a statement
//	@Description	Creates or reuses a SystemComponent from the provided DefinedComponent and links it via ByComponent to the statement.
//	@Tags			System Security Plans
//	@Accept			json
//	@Param			id		path	string					true	"SSP ID"
//	@Param			reqId	path	string					true	"Implemented Requirement ID"
//	@Param			stmtId	path	string					true	"Statement ID"
//	@Param			request	body	ApplySuggestionRequest	true	"Suggestion to apply"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/apply-suggestion [post]
func (h *SystemSecurityPlanHandler) ApplySuggestionForStatement(ctx echo.Context) error {
	sspID, reqID, stmtID, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid statement apply path params", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var payload ApplySuggestionRequest
	if err := ctx.Bind(&payload); err != nil {
		h.sugar.Warnw("Invalid statement apply-suggestion request payload", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := payload.Validate(); err != nil {
		h.sugar.Warnw("Invalid statement apply-suggestion request payload", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.suggestionService.ApplySuggestionForStatement(
		sspID,
		reqID,
		stmtID,
		*payload.ComponentDefinitionID,
		*payload.DefinedComponentID,
	); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to apply statement component suggestions", "sspID", sspID, "reqID", reqID, "stmtID", stmtID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// ApplySuggestionsForStatement godoc
//
//	@Summary		Apply all component suggestions for a statement
//	@Description	Creates SystemComponents from all matching DefinedComponents and links them via ByComponent to the statement.
//	@Tags			System Security Plans
//	@Param			id		path	string	true	"SSP ID"
//	@Param			reqId	path	string	true	"Implemented Requirement ID"
//	@Param			stmtId	path	string	true	"Statement ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/control-implementation/implemented-requirements/{reqId}/statements/{stmtId}/apply-suggestions [post]
func (h *SystemSecurityPlanHandler) ApplySuggestionsForStatement(ctx echo.Context) error {
	sspID, reqID, stmtID, err := parseSSPReqStmtIDs(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid statement apply-suggestions path params", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.suggestionService.ApplyForStatement(sspID, reqID, stmtID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw(
			"failed to apply all statement component suggestions",
			"sspID",
			sspID,
			"reqID",
			reqID,
			"stmtID",
			stmtID,
			"error",
			err,
		)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// BulkApplyComponentSuggestions godoc
//
//	@Summary		Bulk apply component suggestions for all implemented requirements in an SSP
//	@Description	For each ImplementedRequirement, creates SystemComponents from matching DefinedComponents and links them via ByComponent.
//	@Tags			System Security Plans
//	@Param			id	path	string	true	"SSP ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/bulk-apply-component-suggestions [post]
func (h *SystemSecurityPlanHandler) BulkApplyComponentSuggestions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	sspID, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid SSP id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if err := h.suggestionService.ApplyForSSP(sspID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to bulk apply component suggestions", "sspID", sspID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

func parseSSPReqStmtIDs(ctx echo.Context) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	sspID, reqID, err := parseSSPReqIDs(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	stmtID, err := uuid.Parse(ctx.Param("stmtId"))
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	return sspID, reqID, stmtID, nil
}

func parseSSPReqIDs(ctx echo.Context) (uuid.UUID, uuid.UUID, error) {
	sspID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	reqID, err := uuid.Parse(ctx.Param("reqId"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return sspID, reqID, nil
}

// validateByComponentImplementationStatus validates the implementation status
// state on a ByComponent. When the implementation-status field is entirely
// absent (zero JSONType) validation is skipped. When the object is present,
// a valid, non-empty state is required.
func validateByComponentImplementationStatus(bc *relational.ByComponent) error {
	if bc.ImplementationStatus == (datatypes.JSONType[relational.ImplementationStatus]{}) {
		return nil
	}
	is := bc.ImplementationStatus.Data()
	return is.Validate()
}
