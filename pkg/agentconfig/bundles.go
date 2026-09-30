package agentconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v2"
)

// ModulePathPattern is the allowed shape of a module path inside a policy bundle.
var ModulePathPattern = regexp.MustCompile(`^[A-Za-z0-9_\-./]+\.(rego|json|yaml|yml)$`)

// DataFileNames are the only non-Rego files OPA loads from a policy path (R18).
var DataFileNames = []string{"data.json", "data.yaml", "data.yml"}

// ValidateModulePath checks a module path: it matches ModulePathPattern, is relative to the
// policy root (no leading '/'), has no empty, '.' or '..' segment, and a non-.rego file must
// be named data.json, data.yaml or data.yml.
func ValidateModulePath(p string) error {
	if !ModulePathPattern.MatchString(p) {
		return fmt.Errorf("module path %q must match %s", p, ModulePathPattern.String())
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("module path %q must be relative to the policy root", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("module path %q must not contain empty, '.' or '..' segments", p)
		}
	}
	if !strings.HasSuffix(p, ".rego") && !slices.Contains(DataFileNames, path.Base(p)) {
		return fmt.Errorf("module path %q: only .rego modules and data.json, data.yaml or data.yml data files are loaded", p)
	}
	return nil
}

// ValidateBundles checks the shape of policy bundles without OPA (R18, R28):
//   - the name matches BundleNamePattern and the bundle is non-nil;
//   - extends, when set, is non-empty and not inline: (no chaining);
//   - at least one of extends / modules / data is set;
//   - every module path passes ValidateModulePath; each module is at most MaxModuleBytes and
//     the bundle total (modules plus json(data)) at most MaxBundleBytes;
//   - data files parse (JSON, or YAML for .yaml/.yml);
//   - data and a root-level data.json/data.yaml/data.yml module are not both set;
//   - delete requires extends, each entry passes ValidateModulePath and is not also in
//     modules.
//
// All problems have Severity "error". The result is sorted by bundle, path, row, col.
func ValidateBundles(b map[string]*PolicyBundle) []PolicyError {
	return issuesToPolicyErrors(validateBundles(b, false))
}

func issuesToPolicyErrors(issues []bundleIssue) []PolicyError {
	if len(issues) == 0 {
		return nil
	}
	out := make([]PolicyError, 0, len(issues))
	for _, i := range issues {
		out = append(out, i.PolicyError)
	}
	SortPolicyErrors(out)
	return out
}

// validateBundles implements ValidateBundles. With partial set, the bundles are overlay
// patches rather than complete bundles: the two rules that need the merged bundle ("at least
// one of extends/modules/data" and "delete requires extends") are skipped; they are checked
// on the effective config (ValidateEditable) and by the agent.
func validateBundles(b map[string]*PolicyBundle, partial bool) []bundleIssue {
	var issues []bundleIssue
	for _, name := range sortedKeys(b) {
		bundle := b[name]
		add := func(modulePath, field, code, format string, args ...any) {
			issues = append(issues, bundleIssue{
				PolicyError: PolicyError{Bundle: name, Path: modulePath, Message: fmt.Sprintf(format, args...), Severity: SeverityError},
				code:        code,
				field:       field,
			})
		}
		if !BundleNamePattern.MatchString(name) {
			add("", "", FieldCodePattern, "bundle name %q must match %s", name, BundleNamePattern.String())
		}
		if bundle == nil {
			add("", "", FieldCodeRequired, "bundle %q has no definition", name)
			continue
		}
		if bundle.Extends != nil {
			ext := strings.TrimSpace(*bundle.Extends)
			switch {
			case ext == "":
				add("", "/extends", FieldCodeSource, "extends must not be empty")
			case IsInlineSource(ext):
				add("", "/extends", FieldCodeSource, "extends must be an OCI tag or a local path, not an inline bundle")
			}
		}
		if !partial && bundle.Extends == nil && len(bundle.Modules) == 0 && bundle.Data == nil {
			add("", "", FieldCodeRequired, "bundle must set at least one of extends, modules or data")
		}

		total := 0
		for _, modulePath := range sortedKeys(bundle.Modules) {
			src := bundle.Modules[modulePath]
			total += len(src)
			if err := ValidateModulePath(modulePath); err != nil {
				add(modulePath, "", FieldCodePattern, "%s", err.Error())
				continue
			}
			if len(src) > MaxModuleBytes {
				add(modulePath, "", FieldCodeSize, "module is %d bytes; the limit is %d", len(src), MaxModuleBytes)
			}
			if !strings.HasSuffix(modulePath, ".rego") {
				if err := parseDataFile(modulePath, src); err != nil {
					add(modulePath, "", FieldCodeParse, "data file does not parse: %s", err.Error())
				}
			}
		}
		if bundle.Data != nil {
			raw, err := json.Marshal(bundle.Data)
			if err != nil {
				add("", "/data", FieldCodeInvalidType, "data is not JSON-encodable: %s", err.Error())
			}
			total += len(raw)
			for _, f := range DataFileNames {
				if _, ok := bundle.Modules[f]; ok {
					add(f, "", FieldCodeConflict, "set either data or a root-level %s module, not both", f)
				}
			}
		}
		if total > MaxBundleBytes {
			add("", "", FieldCodeSize, "bundle is %d bytes; the limit is %d", total, MaxBundleBytes)
		}

		if len(bundle.Delete) > 0 && bundle.Extends == nil && !partial {
			add("", "/delete", FieldCodeConflict, "delete requires extends")
		}
		for i, p := range bundle.Delete {
			field := "/delete/" + fmt.Sprint(i)
			if err := ValidateModulePath(p); err != nil {
				add(p, field, FieldCodePattern, "%s", err.Error())
				continue
			}
			if _, ok := bundle.Modules[p]; ok {
				add(p, field, FieldCodeConflict, "%q is both deleted and set in modules", p)
			}
		}
	}
	return issues
}

// parseDataFile checks that a data module parses as JSON or YAML (by extension).
func parseDataFile(modulePath, src string) error {
	var v any
	switch {
	case strings.HasSuffix(modulePath, ".json"):
		return json.Unmarshal([]byte(src), &v)
	case strings.HasSuffix(modulePath, ".yaml"), strings.HasSuffix(modulePath, ".yml"):
		return yaml.Unmarshal([]byte(src), &v)
	default:
		return errors.New("unsupported data file type")
	}
}
