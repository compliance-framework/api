package oscal

import (
	"github.com/spf13/cobra"
)

var (
	RootCmd = &cobra.Command{
		Use:   "oscal",
		Short: "OSCAL related commands",
	}
)

func init() {
	RootCmd.AddCommand(newImportCMD())
}
