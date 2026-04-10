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

// ProfileControlResolver resolves the full set of (catalogID, controlID) pairs for a profile.
// Defined as an interface to avoid a circular import between the worker and oscal handler packages.
// The implementation is injected at wire-up time in cmd/run.go using a closure over
// oscalhandler.FindFullProfile and oscalhandler.GetControlIDsMapFromProfile.
type ProfileControlResolver interface {
	ResolveProfileControlKeys(ctx context.Context, profileID uuid.UUID) ([]riskrel.ControlKey, error)
}

// RiskOrphanedCleanupWorker is enqueued by the SSP profile attach endpoint whenever the
// profile binding changes. It resolves the new profile's full control set and transitions
// any open auto-generated risks whose linked controls are no longer present in that set to
// the "remediated" status.
//
// Design rationale:
//   - The handler enqueues a job rather than calling RemediateOrphanedRisks inline so that
//     the HTTP response is not blocked by potentially expensive profile resolution.
//   - River's ByArgs deduplication (scoped to ssp_id + new_profile_id) ensures that each
//     unique profile change on an SSP produces its own job. ByState is overridden to exclude
//     completed/cancelled jobs so that a second change to the same target profile within the
//     River job-cleaner window still triggers a fresh cleanup pass.
//   - No ByPeriod is set, so rapid successive changes are never silently collapsed.
type RiskOrphanedCleanupWorker struct {
	db              *gorm.DB
	riskService     *riskrel.RiskService
	profileResolver ProfileControlResolver
	logger          *zap.SugaredLogger
}

// NewRiskOrphanedCleanupWorker constructs a RiskOrphanedCleanupWorker.
// profileResolver must be non-nil; it is injected from cmd/run.go to avoid a circular import.
func NewRiskOrphanedCleanupWorker(db *gorm.DB, riskService *riskrel.RiskService, profileResolver ProfileControlResolver, logger *zap.SugaredLogger) *RiskOrphanedCleanupWorker {
	return &RiskOrphanedCleanupWorker{
		db:              db,
		riskService:     riskService,
		profileResolver: profileResolver,
		logger:          logger,
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
	// risks are orphaned by definition, so we pass an empty set.
	newControlSet := make(map[riskrel.ControlKey]struct{})

	if args.NewProfileID != nil {
		controlKeys, err := w.profileResolver.ResolveProfileControlKeys(ctx, *args.NewProfileID)
		if err != nil {
			return fmt.Errorf("risk orphaned cleanup: resolve profile controls for ssp %s: %w", args.SSPID, err)
		}
		for _, ck := range controlKeys {
			newControlSet[ck] = struct{}{}
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
