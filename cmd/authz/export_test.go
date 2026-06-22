package authz

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// execExport runs the export command in-process with the given args, capturing its output.
func execExport(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newExportCMD()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestExportCommandDefaultsToJSONOnStdout(t *testing.T) {
	out, err := execExport(t)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, `"schemaVersion"`) {
		t.Errorf("default (json) output missing schemaVersion:\n%s", out)
	}
}

func TestExportCommandFormatFlag(t *testing.T) {
	out, err := execExport(t, "--format", "cedar")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "namespace CCF {") {
		t.Errorf("cedar output missing namespace:\n%s", out)
	}
}

func TestExportCommandWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vocab.openfga")
	out, err := execExport(t, "-f", "openfga", "-o", path)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected no stdout when writing to a file, got %q", out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), "schema 1.1") {
		t.Errorf("output file missing openfga model:\n%s", data)
	}
}

func TestExportCommandUnknownFormatErrors(t *testing.T) {
	if _, err := execExport(t, "-f", "toml"); err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}
