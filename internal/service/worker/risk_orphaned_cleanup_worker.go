package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/compliance-framework/api/internal/service/relational"
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
// profile binding changes. At execution time, it resolves the SSP's current profile control
// set and transitions any open auto-generated risks whose linked controls are no longer
// present in that set to the "remediated" status.
//
// Design rationale:
//   - The handler enqueues a job rather than calling RemediateOrphanedRisks inline so that
//     the HTTP response is not blocked by potentially expensive profile resolution.
//   - River's ByArgs deduplication is scoped to ssp_id + new_profile_id. Active jobs for
//     repeated changes to the same target profile are collapsed, while changes to different
//     targets can enqueue independent jobs.
//   - The worker reloads the current SSP profile at execution time so stale jobs remediate
//     against the latest committed binding.
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

// Work implements river.Worker. It resolves the current profile's control set and delegates
// to RiskService.RemediateOrphanedRisks.
func (w *RiskOrphanedCleanupWorker) Work(ctx context.Context, job *river.Job[RiskOrphanedCleanupArgs]) error {
	args := job.Args
	w.logger.Infow("risk orphaned cleanup: starting",
		"ssp_id", args.SSPID,
		"old_profile_id", args.OldProfileID,
		"new_profile_id", args.NewProfileID,
	)

	db := w.db.WithContext(ctx)

	var ssp relational.SystemSecurityPlan
	if err := db.Select("id", "profile_id").First(&ssp, "id = ?", args.SSPID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.logger.Infow("risk orphaned cleanup: ssp not found, skipping",
				"ssp_id", args.SSPID,
				"old_profile_id", args.OldProfileID,
				"new_profile_id", args.NewProfileID,
			)
			return nil
		}
		return fmt.Errorf("risk orphaned cleanup: load current ssp %s: %w", args.SSPID, err)
	}

	if !uuidPtrEqual(ssp.ProfileID, args.NewProfileID) {
		w.logger.Infow("risk orphaned cleanup: job profile is stale, using current SSP profile",
			"ssp_id", args.SSPID,
			"job_new_profile_id", args.NewProfileID,
			"current_profile_id", ssp.ProfileID,
		)
	}

	// Build the current profile's control set.
	// If ProfileID is nil the SSP's profile binding was cleared, so all auto-generated
	// risks are orphaned by definition and we pass an empty set.
	newControlSet := make(map[riskrel.ControlKey]struct{})

	if ssp.ProfileID != nil {
		controlKeys, err := w.profileResolver.ResolveProfileControlKeys(ctx, *ssp.ProfileID)
		if err != nil {
			return fmt.Errorf("risk orphaned cleanup: resolve profile controls for ssp %s: %w", args.SSPID, err)
		}
		for _, ck := range controlKeys {
			newControlSet[ck] = struct{}{}
		}
	}

	var remediated int
	if err := db.Transaction(func(tx *gorm.DB) error {
		var err error
		remediated, err = w.riskService.RemediateOrphanedRisks(tx, args.SSPID, newControlSet)
		return err
	}); err != nil {
		return fmt.Errorf("risk orphaned cleanup: remediate for ssp %s: %w", args.SSPID, err)
	}

	w.logger.Infow("risk orphaned cleanup: complete",
		"ssp_id", args.SSPID,
		"remediated_count", remediated,
	)
	return nil
}

func uuidPtrEqual(a, b *uuid.UUID) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}
