package dashboards

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func newDashboardsImportCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import dashboard filters from JSON",
		Long:  "Reads a JSON array of filters and creates Filter records and their control relations.",
		Run:   importDashboards,
	}

	cmd.Flags().StringP("file", "f", "", "Input JSON file containing filters")
	cmd.MarkFlagRequired("file")

	return cmd
}

func importDashboards(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer zapLogger.Sync()

	cfg := config.NewConfig(sugar)

	inputFile, err := cmd.Flags().GetString("file")
	if err != nil {
		panic(err)
	}

	db, err := service.ConnectSQLDb(context.Background(), cfg, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	// Read and decode input JSON
	f, err := os.Open(inputFile)
	if err != nil {
		sugar.Fatalf("failed to open input file: %v", err)
	}
	defer f.Close()

	var inputs []dashboardJSON
	if err := json.NewDecoder(f).Decode(&inputs); err != nil {
		sugar.Fatalf("failed to decode input JSON: %v", err)
	}

	created := 0
	for _, in := range inputs {
		rec := relational.Filter{
			Name: in.Name,
		}

		// Build filter JSON if provided
		if in.Filter != nil {
			lf := labelfilter.Filter{Scope: in.Filter.Scope}
			rec.Filter = datatypes.NewJSONType(lf)
		}

		if err := db.Create(&rec).Error; err != nil {
			sugar.Fatalf("failed to create filter '%s': %v", in.Name, err)
		}

		// Resolve and link controls if provided
		if len(in.Controls) > 0 {
			controls := make([]relational.Control, 0, len(in.Controls))
			for _, cr := range in.Controls {
				var ctl relational.Control
				if err := db.Where("catalog_id = ? AND id = ?", cr.CatalogID, cr.ID).First(&ctl).Error; err != nil {
					sugar.Fatalf("control not found for catalog '%s' id '%s': %v", cr.CatalogID, cr.ID, err)
				}
				controls = append(controls, ctl)
			}
			if err := db.Model(&rec).Association("Controls").Replace(controls); err != nil {
				sugar.Fatalf("failed linking controls for filter '%s': %v", in.Name, err)
			}
		}

		created++
		sugar.Infow("Created filter", "name", rec.Name)
	}

	sugar.Infof("Successfully imported %d filters from %s", created, inputFile)
}
