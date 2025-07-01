package seed

import (
	"github.com/spf13/cobra"
)

var (
	RootCmd = &cobra.Command{
		Use:   "seed",
		Short: "Seeding commands",
	}
)

func init() {
	RootCmd.AddCommand(newHeartbeatCMD())
	RootCmd.AddCommand(newEvidenceCMD())
}
