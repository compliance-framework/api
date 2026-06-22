package authz

import (
	"fmt"
	"os"
	"strings"

	"github.com/compliance-framework/api/internal/authz"
	"github.com/spf13/cobra"
)

func newExportCMD() *cobra.Command {
	formats := make([]string, len(authz.SupportedExportFormats))
	for i, f := range authz.SupportedExportFormats {
		formats[i] = string(f)
	}

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the authorization vocabulary",
		Long: "Render the embedded authorization manifest (subjects, resources, actions, attributes\n" +
			"and default roles) into a target format for external PDPs and GitOps pipelines.\n" +
			"This exports the vocabulary, not operator policies.\n\n" +
			"Formats: " + strings.Join(formats, " | "),
		RunE: runExport,
	}

	cmd.Flags().StringP("format", "f", string(authz.ExportJSON), "Output format ("+strings.Join(formats, " | ")+")")
	cmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	return cmd
}

func runExport(cmd *cobra.Command, _ []string) error {
	formatFlag, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	format, err := authz.ParseExportFormat(formatFlag)
	if err != nil {
		return err
	}
	outputFile, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	manifest, err := authz.DefaultManifest()
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	out, err := manifest.Export(format)
	if err != nil {
		return err
	}

	if outputFile == "" {
		_, err = cmd.OutOrStdout().Write(out)
		return err
	}
	if err := os.WriteFile(outputFile, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outputFile, err)
	}
	return nil
}
