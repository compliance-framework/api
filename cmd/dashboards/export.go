package dashboards

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newDashboardsExportCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export dashboards from the system",
		Long:  "This command allows you to export dashboards from the compliance framework configuration service.",
		Run:   exportDashboards,
	}

	cmd.Flags().StringP("output", "o", "dashboards_export.json", "Output file for exported dashboards")
	failOnError(cmd.MarkFlagRequired("output"))

	return cmd
}

func exportDashboards(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer func() {
		_ = zapLogger.Sync() // Flushes buffer, if any. We ignore errors here (that are commonly-seen) as distracting and not of note.
	}()

	config := config.NewConfig(sugar)

	outputFile, err := cmd.Flags().GetString("output")
	if err != nil {
		panic(err)
	}

	db, err := service.ConnectSQLDb(context.Background(), config, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	var dashboards []relational.Filter
	if err := db.
		Select("id", "name", "ssp_id", "filter").
		Preload("Controls", func(db *gorm.DB) *gorm.DB {
			return db.Select("id", "catalog_id")
		}).
		Find(&dashboards).Error; err != nil {
		sugar.Fatalf("failed to fetch dashboards: %v", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		sugar.Fatalf("failed to create output file: %v", err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			sugar.Errorf("failed to close output file: %v", err)
		}
	}()

	// Map to export DTOs to omit empty/null values and Filter.ID
	exports := make([]dashboardJSON, 0, len(dashboards))
	for _, f := range dashboards {
		fe := dashboardJSON{
			Name:  f.Name,
			SSPID: f.SSPID,
		}
		// Extract underlying filter and omit if empty
		lf := f.Filter.Data()
		fe.Filter = &lf
		if len(f.Controls) > 0 {
			ctrls := make([]controlRef, len(f.Controls))
			for i, c := range f.Controls {
				ctrls[i] = controlRef{CatalogID: c.CatalogID, ID: c.ID}
			}
			fe.Controls = ctrls
		}
		exports = append(exports, fe)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(exports); err != nil {
		sugar.Fatalf("failed to write dashboards to file: %v", err)
	}

	sugar.Infof("Successfully exported %d dashboards to %s", len(dashboards), outputFile)
}
