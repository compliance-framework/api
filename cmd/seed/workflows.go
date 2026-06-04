package seed

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newWorkflowsCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflows",
		Short: "Import workflow definitions from JSON",
		Run:   importSeedWorkflows,
	}

	cmd.Flags().StringP("file", "f", "", "Input JSON file containing workflow definitions")
	if err := cmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	return cmd
}

func importSeedWorkflows(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer func() {
		_ = zapLogger.Sync()
	}()

	inputFile, err := cmd.Flags().GetString("file")
	if err != nil {
		sugar.Fatalf("failed to get input file flag: %v", err)
	}

	cfg := config.NewConfig(sugar)
	db, err := service.ConnectSQLDb(context.Background(), cfg, sugar)
	if err != nil {
		sugar.Fatalf("failed to connect database: %v", err)
	}

	summary, err := importWorkflowsFromFile(context.Background(), db, sugar, inputFile)
	if err != nil {
		sugar.Fatalf("failed to import workflow seed: %v", err)
	}

	sugar.Infow("Workflow seed import completed",
		"definitions_created", summary.DefinitionsCreated,
		"definitions_updated", summary.DefinitionsUpdated,
		"steps", summary.Steps,
		"dependencies", summary.Dependencies,
		"control_relationships", summary.ControlRelationships,
		"instances", summary.Instances,
		"role_assignments", summary.RoleAssignments,
		"skipped", summary.Skipped,
		"failed", summary.Failed,
	)
	if summary.Failed > 0 {
		sugar.Fatalf("workflow seed import completed with %d failed definitions", summary.Failed)
	}
}

func importWorkflowsFromFile(ctx context.Context, db *gorm.DB, sugar *zap.SugaredLogger, path string) (workflows.SeedSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return workflows.SeedSummary{}, fmt.Errorf("failed to open input file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && sugar != nil {
			sugar.Errorw("failed to close input file", "error", closeErr)
		}
	}()

	definitions, err := workflows.DecodeSeedDefinitions(f)
	if err != nil {
		return workflows.SeedSummary{}, fmt.Errorf("failed to decode input JSON: %w", err)
	}

	return workflows.ImportSeedDefinitions(ctx, db, sugar, definitions), nil
}
