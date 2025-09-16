package dashboards

import "github.com/spf13/cobra"

var (
	RootCmd = &cobra.Command{
		Use:   "dashboards",
		Short: "Dashboard related commands",
	}
)

func init() {
	// export
	RootCmd.AddCommand(newImportCMD())
	// import
	RootCmd.AddCommand(newDashboardsImportCMD())
}
