package worker

import (
	"context"
	"fmt"

	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RiskOrphanedCleanupWorker is enqueued synchronously by the SSP profile attach/update
// endpoints whenever the profile binding changes. It resolves the new profile's full control
// set and transitions any open auto-generated risks whose linked controls are no longer
// present in that set to the "remediated" status.
//
// Design rationale:
//   - The handler enqueues a job rather than calling RemediateOrphanedRisks inline so that
//     the HTTP response is not blocked by potentially expensive profile resolution.
//   - River's ByArgs deduplication ensures that each unique (ssp_id, new_profile_id) pair
//     produces its own job, so multiple profile changes on the same SSP within a short window
//     each trigger an independent cleanup pass.
//   - No ByPeriod is set, so rapid successive changes are never silently collapsed.
type RiskOrphanedCleanupWorker struct {
	db          *gorm.DB
	riskService *riskrel.RiskService
	logger      *zap.SugaredLogger
}

// NewRiskOrphanedCleanupWorker constructs a RiskOrphanedCleanupWorker.
func NewRiskOrphanedCleanupWorker(db *gorm.DB, riskService *riskrel.RiskService, logger *zap.SugaredLogger) *RiskOrphanedCleanupWorker {
	return &RiskOrphanedCleanupWorker{
		db:          db,
		riskService: riskService,
		logger:      logger,
	}
}

// Work implements river.Worker. It resolves the new profile's control set and delegates
// to RiskService.RemediateOrphanedRisks.
func (w *RiskOrphanedCleanupWorker) Work(ctx context.Context, job *river.Job[RiskOrphanedCleanupArgs]) error {
	args := job.Args
	w.logger.Infow("risk orphaned cleanup: starting",
		"ssp_id", args.SSPID,
		"old_profile_id", args.OldProfileID,
		"new_profile_id", args.NewProfileID,
	)

	// Build the new profile's control set.
	// If NewProfileID is nil the SSP's profile binding was cleared — all auto-generated
	// risks are orphaned, so we pass an empty set.
	newControlSet := make(map[riskrel.ControlKey]struct{})

	if args.NewProfileID != nil {
		controlIDs, err := w.resolveProfileControlIDs(ctx, *args.NewProfileID)
		if err != nil {
			return fmt.Errorf("risk orphaned cleanup: resolve profile controls for ssp %s: %w", args.SSPID, err)
		}
		for _, id := range controlIDs {
			newControlSet[riskrel.ControlKey{ControlID: id}] = struct{}{}
		}
	}

	remediated, err := w.riskService.RemediateOrphanedRisks(w.db.WithContext(ctx), args.SSPID, newControlSet)
	if err != nil {
		return fmt.Errorf("risk orphaned cleanup: remediate for ssp %s: %w", args.SSPID, err)
	}

	w.logger.Infow("risk orphaned cleanup: complete",
		"ssp_id", args.SSPID,
		"remediated_count", remediated,
	)
	return nil
}

// resolveProfileControlIDs returns all control IDs for a given profile using the same
// two-step resolution as the SSP handler:
//  1. Pivot table (profile_controls) — fast path, populated by SyncProfileControls
//  2. Direct join through the profile → controls many2many — fallback when pivot is empty
func (w *RiskOrphanedCleanupWorker) resolveProfileControlIDs(ctx context.Context, profileID uuid.UUID) ([]string, error) {
	// Step 1: pivot table (fast path)
	var controlIDs []string
	if err := w.db.WithContext(ctx).
		Table("profile_controls").
		Distinct("control_id").
		Where("profile_id = ?", profileID).
		Pluck("control_id", &controlIDs).Error; err != nil {
		w.logger.Warnw("risk orphaned cleanup: pivot table lookup failed, falling back to join",
			"profile_id", profileID, "error", err)
	}

	if len(controlIDs) > 0 {
		return controlIDs, nil
	}

	// Step 2: direct join — profile_controls may not be populated yet for new profiles
	// (SyncProfileControls runs asynchronously). Fall back to querying the join table
	// that backs the Profile.Controls many2many association.
	w.logger.Infow("risk orphaned cleanup: pivot table empty, falling back to direct join",
		"profile_id", profileID)

	if err := w.db.WithContext(ctx).
		Table("profile_controls").
		Distinct("control_id").
		Where("profile_id IN (?)",
			w.db.Table("profiles").Select("id").Where("id = ?", profileID),
		).
		Pluck("control_id", &controlIDs).Error; err != nil {
		return nil, fmt.Errorf("resolveProfileControlIDs: direct join query failed: %w", err)
	}

	return controlIDs, nil
}
