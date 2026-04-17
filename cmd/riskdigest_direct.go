package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type riskOpenDigestDirectResult struct {
	WindowKind              string
	WindowStart             time.Time
	WindowEnd               time.Time
	RecipientCount          int
	AttemptedRecipientCount int
	ErrorCount              int
}

func sendRiskOpenDigestNow(
	ctx context.Context,
	db *gorm.DB,
	emailService worker.EmailService,
	slackService worker.SlackService,
	userRepo worker.UserRepository,
	webBaseURL string,
	windowKind string,
	logger *zap.SugaredLogger,
) (*riskOpenDigestDirectResult, error) {
	return sendRiskOpenDigestAtTime(ctx, db, emailService, slackService, userRepo, webBaseURL, windowKind, logger, time.Now().UTC())
}

func sendRiskOpenDigestAtTime(
	ctx context.Context,
	db *gorm.DB,
	emailService worker.EmailService,
	slackService worker.SlackService,
	userRepo worker.UserRepository,
	webBaseURL string,
	windowKind string,
	logger *zap.SugaredLogger,
	now time.Time,
) (*riskOpenDigestDirectResult, error) {
	if db == nil {
		return nil, fmt.Errorf("risk digest direct run: db is required")
	}
	if emailService == nil {
		return nil, fmt.Errorf("risk digest direct run: email service is required")
	}
	if userRepo == nil {
		return nil, fmt.Errorf("risk digest direct run: user repository is required")
	}

	plan, err := worker.BuildRiskOpenDigestPlan(ctx, db, windowKind, now.UTC(), logger)
	if err != nil {
		return nil, fmt.Errorf("risk digest direct run: %w", err)
	}

	result := &riskOpenDigestDirectResult{
		WindowKind:     plan.WindowKind,
		WindowStart:    plan.WindowStart,
		WindowEnd:      plan.WindowEnd,
		RecipientCount: len(plan.RecipientUserIDs),
	}
	if len(plan.RecipientUserIDs) == 0 {
		if logger != nil {
			logger.Infow("Risk digest direct run: no recipients found", "window_kind", plan.WindowKind)
		}
		return result, nil
	}

	riskNotificationServiceFactory := worker.NewDirectRiskNotificationServiceFactory(emailService, slackService)
	digestWorker := worker.NewRiskOpenDigestWorker(db, userRepo, webBaseURL, riskNotificationServiceFactory, logger)

	var runErrors []error
	for _, recipientID := range plan.RecipientUserIDs {
		result.AttemptedRecipientCount++

		err := digestWorker.Work(ctx, &river.Job[worker.RiskOpenDigestArgs]{
			Args: worker.RiskOpenDigestArgs{
				RecipientUserID: recipientID,
				WindowStart:     plan.WindowStart.Format(time.RFC3339),
				WindowEnd:       plan.WindowEnd.Format(time.RFC3339),
				WindowKind:      plan.WindowKind,
			},
		})
		if err == nil {
			continue
		}

		result.ErrorCount++
		runErrors = append(runErrors, fmt.Errorf("recipient %s: %w", recipientID, err))
		if logger != nil {
			logger.Errorw("Risk digest direct run: recipient failed",
				"user_id", recipientID,
				"error", err,
			)
		}
	}

	if len(runErrors) > 0 {
		return result, fmt.Errorf("risk digest direct run failed for %d recipients: %w", len(runErrors), errors.Join(runErrors...))
	}

	if logger != nil {
		logger.Infow("Risk digest direct run completed",
			"window_kind", result.WindowKind,
			"window_start", result.WindowStart,
			"window_end", result.WindowEnd,
			"recipient_count", result.RecipientCount,
			"attempted_recipient_count", result.AttemptedRecipientCount,
		)
	}

	return result, nil
}
