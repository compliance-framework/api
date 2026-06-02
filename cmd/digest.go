package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/logging"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/email"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	dryRun bool

	DigestCmd = &cobra.Command{
		Use:   "digest",
		Short: "Digest management commands",
	}

	digestTestCmd = &cobra.Command{
		Use:   "test",
		Short: "Test the digest by sending it immediately to all subscribed users",
		Run:   runDigestTest,
	}

	digestPreviewCmd = &cobra.Command{
		Use:   "preview",
		Short: "Preview the digest summary without sending emails",
		Run:   runDigestPreview,
	}
)

func init() {
	digestTestCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be sent without sending emails")
	DigestCmd.AddCommand(digestTestCmd)
	DigestCmd.AddCommand(digestPreviewCmd)
}

func runDigestTest(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	var sugar *zap.SugaredLogger
	if viper.GetBool("use_dev_logger") {
		sugar = zap.Must(zap.NewDevelopment()).Sugar()
	} else {
		sugar = zap.Must(zap.NewProduction()).Sugar()
	}

	defer func() {
		if err := sugar.Sync(); !logging.IgnoreSyncError(err) {
			log.Printf("failed to sync zap logger: %v", err)
		}
	}()

	cfg := config.NewConfig(sugar)

	// Check if this is production and add confirmation if not dry-run
	if cfg.Environment == "production" && !dryRun {
		fmt.Print("⚠️  WARNING: You are about to send digest emails to all subscribed users in PRODUCTION!\n")
		fmt.Print("This will send emails to real users. Are you sure you want to continue? (type 'yes' to confirm): ")

		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			sugar.Fatalw("Failed to read user input", "error", err)
		}
		if response != "yes" {
			fmt.Println("Operation cancelled.")
			return
		}
	}

	db, err := service.ConnectSQLDb(ctx, cfg, sugar)
	if err != nil {
		sugar.Fatalw("Failed to connect to SQL database", "error", err)
	}

	emailService, err := email.NewService(cfg.Email, sugar)
	if err != nil {
		sugar.Fatalw("Failed to initialize email service", "error", err)
	}

	slackService, err := slacksvc.NewService(cfg.Slack, sugar)
	if err != nil {
		sugar.Fatalw("Failed to initialize slack service", "error", err)
	}
	runtimeProvider := digest.NewRuntimeProvider(
		emailService,
		nil,
		slackService,
	)

	notifier := digest.NewNotificationService(
		db,
		cfg,
		runtimeProvider,
	)
	digestService := digest.NewService(db, notifier, cfg, sugar)

	if dryRun {
		sugar.Info("Running digest test in DRY-RUN mode (no emails will be sent)...")

		// Get the digest summary without sending
		summary, err := digestService.GetGlobalEvidenceSummary(ctx)
		if err != nil {
			sugar.Fatalw("Failed to get digest summary", "error", err)
		}

		sugar.Infow("Digest summary (dry-run)",
			"total_evidence", summary.TotalCount,
			"satisfied", summary.SatisfiedCount,
			"not_satisfied", summary.NotSatisfiedCount,
			"expired", summary.ExpiredCount,
			"top_not_satisfied_count", len(summary.TopNotSatisfied),
			"top_expired_count", len(summary.TopExpired),
		)

		sugar.Info("Dry-run completed successfully - no emails were sent")
		return
	}

	sugar.Info("Running digest test...")
	if err := digestService.SendGlobalDigest(ctx); err != nil {
		sugar.Fatalw("Failed to send digest", "error", err)
	}

	sugar.Info("Digest test completed successfully")
}

func runDigestPreview(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	var sugar *zap.SugaredLogger
	if viper.GetBool("use_dev_logger") {
		sugar = zap.Must(zap.NewDevelopment()).Sugar()
	} else {
		sugar = zap.Must(zap.NewProduction()).Sugar()
	}

	defer func() {
		if err := sugar.Sync(); !logging.IgnoreSyncError(err) {
			log.Printf("failed to sync zap logger: %v", err)
		}
	}()

	cfg := config.NewConfig(sugar)

	db, err := service.ConnectSQLDb(ctx, cfg, sugar)
	if err != nil {
		sugar.Fatalw("Failed to connect to SQL database", "error", err)
	}

	emailService, err := email.NewService(cfg.Email, sugar)
	if err != nil {
		sugar.Warnw("Failed to initialize email service", "error", err)
	}

	slackService, err := slacksvc.NewService(cfg.Slack, sugar)
	if err != nil {
		sugar.Warnw("Failed to initialize slack service", "error", err)
	}
	runtimeProvider := digest.NewRuntimeProvider(
		emailService,
		nil,
		slackService,
	)

	notifier := digest.NewNotificationService(
		db,
		cfg,
		runtimeProvider,
	)
	digestService := digest.NewService(db, notifier, cfg, sugar)

	summary, err := digestService.GetGlobalEvidenceSummary(ctx)
	if err != nil {
		sugar.Fatalw("Failed to get evidence summary", "error", err)
	}

	recipients, err := digestService.GetDigestRecipients(ctx)
	if err != nil {
		sugar.Fatalw("Failed to get digest recipients", "error", err)
	}

	fmt.Println("\n=== Evidence Digest Preview ===")
	fmt.Printf("Total Evidence: %d\n", summary.TotalCount)
	fmt.Printf("Satisfied: %d\n", summary.SatisfiedCount)
	fmt.Printf("Not Satisfied: %d\n", summary.NotSatisfiedCount)
	fmt.Printf("Expired: %d\n", summary.ExpiredCount)
	fmt.Printf("Other: %d\n", summary.OtherCount)
	fmt.Printf("\nSubscribed Users: %d\n", len(recipients))

	if len(summary.TopNotSatisfied) > 0 {
		fmt.Println("\nTop Not Satisfied Evidence:")
		for i, item := range summary.TopNotSatisfied {
			fmt.Printf("  %d. %s (UUID: %s)\n", i+1, item.Title, item.UUID)
		}
	}

	if len(summary.TopExpired) > 0 {
		fmt.Println("\nTop Expired Evidence:")
		for i, item := range summary.TopExpired {
			fmt.Printf("  %d. %s (UUID: %s, Expired: %v)\n", i+1, item.Title, item.UUID, item.ExpiresAt)
		}
	}

	if summary.NotSatisfiedCount == 0 && summary.ExpiredCount == 0 {
		fmt.Println("\n✓ No issues found - digest would be skipped")
	} else {
		fmt.Println("\n✓ Digest would be sent to subscribed users")
	}
}
