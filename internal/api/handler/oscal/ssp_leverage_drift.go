package oscal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
)

// driftedLinkInfo describes one SSPLeverageLink that was just flipped to drifted,
// along with the risk that now represents it downstream — returned so callers can
// enqueue a leverage_drifted/leverage_revoked notification after their transaction
// commits (BCH-1341).
type driftedLinkInfo struct {
	LinkID          uuid.UUID
	DownstreamSSPID uuid.UUID
	RiskID          uuid.UUID
	Reason          string
}

// enqueueLeverageDriftNotifications calls jobEnqueuer once per drifted link — using only
// plain uuid.UUID/string parameters (mirroring EnqueueOrphanedRiskCleanup's shape)
// rather than a shared struct type, since a struct type defined in this package couldn't
// satisfy an interface method implemented by *worker.Service (a different package)
// without introducing a circular import between the oscal and worker packages. A failed
// enqueue is logged and swallowed, not returned — the drift itself already committed
// successfully, and losing a notification shouldn't fail the request that caused it
// (same non-atomicity tradeoff as EnqueueOrphanedRiskCleanup's call sites).
func enqueueLeverageDriftNotifications(ctx context.Context, sugar *zap.SugaredLogger, jobEnqueuer SSPJobEnqueuer, links []driftedLinkInfo) {
	if jobEnqueuer == nil {
		return
	}
	for _, info := range links {
		if err := jobEnqueuer.EnqueueLeverageDriftNotification(ctx, info.RiskID, info.LinkID, info.DownstreamSSPID, info.Reason); err != nil {
			sugar.Warnw("Failed to enqueue leverage drift notification",
				"risk_id", info.RiskID, "link_id", info.LinkID, "error", err)
		}
	}
}

// computeDedupeKeyForLeverageDrift returns the dedupe key for the drift risk
// associated with a single SSPLeverageLink. One risk per leverage link: the link
// itself is the natural, deterministic scope (no risk template is involved, unlike
// evidence-driven risks), and the key is directly parseable back to the link that
// produced it without needing a separate link table.
func computeDedupeKeyForLeverageDrift(linkID uuid.UUID) string {
	return fmt.Sprintf("leverage-drift:%s", linkID)
}

// applyDriftToLink flips an active SSPLeverageLink to drifted and creates (or reopens)
// its inherited-revoked risk. It is the single unit every drift trigger (version bump,
// offering deprecate/revoke, leveraged-authorization delete) calls into. Idempotent: a
// link that isn't currently active is left untouched (zero value, ok=false returned) so
// re-running a trigger never re-drifts or duplicates work.
func applyDriftToLink(tx *gorm.DB, link *relational.SSPLeverageLink, reason string) (info driftedLinkInfo, ok bool, err error) {
	if link.Status != relational.SSPLeverageStatusActive {
		return driftedLinkInfo{}, false, nil
	}

	if err := tx.Model(&relational.SSPLeverageLink{}).
		Where("id = ?", link.ID).
		Update("status", relational.SSPLeverageStatusDrifted).Error; err != nil {
		return driftedLinkInfo{}, false, fmt.Errorf("failed to flip leverage link to drifted: %w", err)
	}
	link.Status = relational.SSPLeverageStatusDrifted

	dedupeKey := computeDedupeKeyForLeverageDrift(*link.ID)

	var existingRisk risks.Risk
	err = tx.Where("dedupe_key = ? AND status != ?", dedupeKey, risks.RiskStatusClosed).First(&existingRisk).Error
	switch {
	case err == nil:
		if updateErr := reopenLeverageDriftRisk(tx, &existingRisk, reason); updateErr != nil {
			return driftedLinkInfo{}, false, updateErr
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		if existingRisk, err = createLeverageDriftRisk(tx, *link, dedupeKey, reason); err != nil {
			return driftedLinkInfo{}, false, err
		}
	default:
		return driftedLinkInfo{}, false, fmt.Errorf("failed to check for existing leverage drift risk: %w", err)
	}

	if err := createLeverageDriftRiskLinks(tx, *existingRisk.ID, *link); err != nil {
		return driftedLinkInfo{}, false, err
	}

	return driftedLinkInfo{
		LinkID:          *link.ID,
		DownstreamSSPID: link.DownstreamSSPID,
		RiskID:          *existingRisk.ID,
		Reason:          reason,
	}, true, nil
}

// createLeverageDriftRisk creates a new inherited-revoked risk for a just-drifted
// leverage link.
func createLeverageDriftRisk(tx *gorm.DB, link relational.SSPLeverageLink, dedupeKey, reason string) (risks.Risk, error) {
	now := time.Now().UTC()

	newRisk := risks.Risk{
		Title:       fmt.Sprintf("Leveraged control %s drifted", link.ControlID),
		Description: fmt.Sprintf("The upstream capability leveraged for control %s changed: %s.", link.ControlID, reason),
		Status:      string(risks.RiskStatusOpen),
		SSPID:       link.DownstreamSSPID,
		SourceType:  string(risks.RiskSourceTypeInheritedRevoked),
		DedupeKey:   dedupeKey,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	if err := tx.Create(&newRisk).Error; err != nil {
		return risks.Risk{}, fmt.Errorf("failed to create leverage drift risk: %w", err)
	}

	if err := emitLeverageDriftRiskEvent(tx, *newRisk.ID, string(risks.RiskEventTypeCreated), map[string]interface{}{
		"leverage_link_id": link.ID,
		"dedupe_key":       dedupeKey,
		"reason":           reason,
	}, now); err != nil {
		return risks.Risk{}, err
	}
	if err := risks.NewRiskService(tx).RecordRiskScoreSnapshot(tx, *newRisk.ID, risks.RiskEventTypeCreated, nil, now); err != nil {
		return risks.Risk{}, fmt.Errorf("failed to record created risk score snapshot: %w", err)
	}

	return newRisk, nil
}

// reopenLeverageDriftRisk reopens a previously-remediated drift risk (re-attested, then
// drifted again) and bumps LastSeenAt on any other non-closed status.
func reopenLeverageDriftRisk(tx *gorm.DB, existingRisk *risks.Risk, reason string) error {
	now := time.Now().UTC()
	previousLastSeen := existingRisk.LastSeenAt

	reopened := false
	oldStatus := existingRisk.Status
	if existingRisk.Status == string(risks.RiskStatusRemediated) {
		existingRisk.Status = string(risks.RiskStatusOpen)
		reopened = true
	}
	existingRisk.LastSeenAt = now

	if err := tx.Save(existingRisk).Error; err != nil {
		return fmt.Errorf("failed to update existing leverage drift risk: %w", err)
	}

	if reopened {
		if err := emitLeverageDriftRiskEvent(tx, *existingRisk.ID, string(risks.RiskEventTypeStatusChange), map[string]interface{}{
			"from":   oldStatus,
			"to":     string(risks.RiskStatusOpen),
			"reason": reason,
		}, now); err != nil {
			return err
		}
		if err := risks.NewRiskService(tx).RecordRiskScoreSnapshot(tx, *existingRisk.ID, risks.RiskEventTypeStatusChange, nil, now); err != nil {
			return fmt.Errorf("failed to record reopened risk score snapshot: %w", err)
		}
	}

	return emitLeverageDriftRiskEvent(tx, *existingRisk.ID, string(risks.RiskEventTypeLastSeen), map[string]interface{}{
		"previous_last_seen": previousLastSeen,
		"new_last_seen":      now,
		"reason":             reason,
	}, now)
}

// createLeverageDriftRiskLinks links a drift risk to every downstream responsibility
// consumer of the leveraged capability (RiskResponsibilityLink, unfiltered — unlike the
// evidence-driven BCH-1339/1340 arm, drift affects the whole leveraged capability, not a
// filter-matched subset) and, best-effort, to the downstream SSP's own catalog control
// entry (RiskControlLink) if one resolves. Both idempotent via OnConflict{DoNothing}.
func createLeverageDriftRiskLinks(tx *gorm.DB, riskID uuid.UUID, link relational.SSPLeverageLink) error {
	now := time.Now().UTC()

	var responsibilities []relational.ControlImplementationResponsibility
	if err := tx.Where("provided_uuid = ?", link.ProvidedUUID).Find(&responsibilities).Error; err != nil {
		return fmt.Errorf("failed to load responsibilities for leverage drift link: %w", err)
	}
	for _, resp := range responsibilities {
		respLink := &risks.RiskResponsibilityLink{
			RiskID:             riskID,
			ResponsibilityUUID: *resp.ID,
			CreatedAt:          now,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(respLink).Error; err != nil {
			return fmt.Errorf("failed to create responsibility link for leverage drift risk: %w", err)
		}
	}

	catalogID, ok, err := resolveCatalogIDForControl(tx, link.DownstreamSSPID, link.ControlID)
	if err != nil {
		return fmt.Errorf("failed to resolve catalog id for leverage drift link: %w", err)
	}
	if ok {
		controlLink := &risks.RiskControlLink{
			RiskID:    riskID,
			CatalogID: catalogID,
			ControlID: link.ControlID,
			CreatedAt: now,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(controlLink).Error; err != nil {
			return fmt.Errorf("failed to create control link for leverage drift risk: %w", err)
		}
	}

	return nil
}

// resolveCatalogIDForControl finds the catalog id a downstream SSP's own profile
// associates with controlID, mirroring the join risk_evidence_worker.go's
// resolveSSPsViaFilters uses for its filter_controls arm. Best-effort: a downstream SSP
// need not have the leveraged control in its own profile at all (it may rely on the
// leveraged capability alone), so a miss is not an error.
func resolveCatalogIDForControl(tx *gorm.DB, downstreamSSPID uuid.UUID, controlID string) (uuid.UUID, bool, error) {
	type catalogRow struct {
		ControlCatalogID uuid.UUID `gorm:"column:control_catalog_id"`
	}
	var rows []catalogRow
	if err := tx.Table("ssp_profiles sp").
		Select("DISTINCT pc.control_catalog_id").
		Joins("JOIN profile_controls pc ON CAST(sp.profile_id AS uuid) = CAST(pc.profile_id AS uuid) AND UPPER(pc.control_id) = UPPER(?)", controlID).
		Where("CAST(sp.system_security_plan_id AS uuid) = CAST(? AS uuid)", downstreamSSPID).
		Scan(&rows).Error; err != nil {
		return uuid.Nil, false, err
	}
	if len(rows) == 0 {
		return uuid.Nil, false, nil
	}
	return rows[0].ControlCatalogID, true, nil
}

// emitLeverageDriftRiskEvent mirrors risk_evidence_worker.go's emitRiskEventAt: builds
// and creates a RiskEvent row directly, since the risks package's own event-logging
// helpers (logRiskEvent/logRiskEventWithSnapshot) are unexported.
func emitLeverageDriftRiskEvent(tx *gorm.DB, riskID uuid.UUID, eventType string, payload map[string]interface{}, occurredAt time.Time) error {
	payloadMap := datatypes.JSONMap(payload)
	details := risks.BuildRiskEventDetails(eventType, payloadMap, occurredAt)

	event := &risks.RiskEvent{
		RiskID:     riskID,
		EventType:  eventType,
		OccurredAt: occurredAt,
		Details:    &details,
		Payload:    payloadMap,
	}

	return tx.Create(event).Error
}

// evaluateLeverageDriftForOffering re-evaluates every SSPLeverageLink pointing at
// offering and drifts the ones whose snapshot is now behind: either the offering's
// Version has moved past what the link recorded at subscribe/re-attest time (covers
// both a real content change and a backing component's ImplementationStatus downgrade,
// since both bump Version via SyncExportOffering), or the offering itself has been
// deprecated/revoked (independent of Version). Must be called within the same
// transaction that persisted the offering's current Version/Status.
func evaluateLeverageDriftForOffering(tx *gorm.DB, offering relational.SSPExportOffering) ([]driftedLinkInfo, error) {
	var links []relational.SSPLeverageLink
	if err := tx.Where("offering_id = ?", offering.ID).Find(&links).Error; err != nil {
		return nil, fmt.Errorf("failed to load leverage links for offering: %w", err)
	}

	var results []driftedLinkInfo
	for i := range links {
		link := links[i]

		var reason string
		switch {
		case offering.Status == relational.SSPExportOfferingStatusDeprecated:
			reason = "upstream offering deprecated"
		case offering.Status == relational.SSPExportOfferingStatusRevoked:
			reason = "upstream offering revoked"
		case offering.Version > link.OfferingVersion:
			reason = "upstream offering content changed"
		default:
			continue
		}

		info, ok, err := applyDriftToLink(tx, &link, reason)
		if err != nil {
			return nil, err
		}
		if ok {
			results = append(results, info)
		}
	}

	return results, nil
}
