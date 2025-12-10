package dashboards

import (
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// Shared data structures for import/export
type controlRef struct {
	CatalogID uuid.UUID `json:"catalog_id,omitempty"`
	ID        string    `json:"id,omitempty"`
}

type dashboardJSON struct {
	ID       *uuid.UUID          `json:"id,omitempty"`
	Name     string              `json:"name,omitempty"`
	Filter   *labelfilter.Filter `json:"filter"`
	Controls []controlRef        `json:"controls,omitempty"`
}

var (
	RootCmd = &cobra.Command{
		Use:   "dashboards",
		Short: "Dashboard related commands",
	}
)

func init() {
	RootCmd.AddCommand(newDashboardsExportCMD())
	RootCmd.AddCommand(newDashboardsImportCMD())
}
