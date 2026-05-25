package cmd

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/logging"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/email"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	riskDigestWindowOverride string

	RiskDigestCmd = &cobra.Command{
		Use:   "riskdigest",
		Short: "Risk digest management commands",
	}

	riskDigestTestCmd = &cobra.Command{
		Use:   "test",
		Short: "Run the risk digest immediately by calling the worker directly",
		Run:   runRiskDigestTest,
	}
)

func init() {
	riskDigestTestCmd.Flags().StringVar(&riskDigestWindowOverride, "window", "", "Override digest window (daily, weekly, none)")
	RiskDigestCmd.AddCommand(riskDigestTestCmd)
}

func runRiskDigestTest(cmd *cobra.Command, args []string) {
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

	if cfg.Environment == "production" {
		fmt.Print("WARNING: You are about to send risk digest notifications directly in PRODUCTION.\n")
		fmt.Print("This will send notifications to real users. Are you sure you want to continue? (type 'yes' to confirm): ")

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

	windowKind := strings.TrimSpace(riskDigestWindowOverride)
	if windowKind == "" && cfg.Risk != nil {
		windowKind = cfg.Risk.OpenDigestWindow
	}

	sugar.Infow("Running risk digest test",
		"window_kind", windowKind,
		"web_base_url", cfg.WebBaseURL,
	)

	result, err := sendRiskOpenDigestNow(
		ctx,
		db,
		emailService,
		slackService,
		worker.NewGORMUserRepository(db),
		cfg.WebBaseURL,
		windowKind,
		sugar,
	)
	if err != nil {
		sugar.Fatalw("Failed to run risk digest test",
			"error", err,
			"window_kind", windowKind,
		)
	}

	sugar.Infow("Risk digest test completed successfully",
		"window_kind", result.WindowKind,
		"window_start", result.WindowStart,
		"window_end", result.WindowEnd,
		"recipient_count", result.RecipientCount,
		"attempted_recipient_count", result.AttemptedRecipientCount,
		"error_count", result.ErrorCount,
	)
}
