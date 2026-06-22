// Package authz provides the `api authz` CLI commands for working with CCF's authorization
// vocabulary — currently `export`, which renders the embedded manifest for external PDPs
// and GitOps pipelines (parent design §3.4; BCH-1314).
package authz

import (
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "authz",
	Short: "Authorization vocabulary commands",
	Long:  "Commands for working with CCF's authorization manifest — the engine-neutral vocabulary operator policies are written against.",
}

func init() {
	RootCmd.AddCommand(newExportCMD())
}
