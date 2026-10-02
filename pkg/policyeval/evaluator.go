// Package policyeval evaluates compliance_framework Rego policies. It is the single
// implementation shared by the agent's policy-manager and the API's playback endpoint, so a
// result from one means the same as a result from the other.
package policyeval

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

// Options tunes evaluation. The zero value reproduces the agent's behaviour: every OPA
// builtin available, wall-clock time, and print() output discarded.
type Options struct {
	// Capabilities restricts the builtins and features policies may use. Nil means all.
	Capabilities *ast.Capabilities
	// Time pins time.now_ns() for every evaluation. Zero means the wall clock.
	Time time.Time
	// PrintHook receives print() output. Nil disables print statements.
	PrintHook print.Hook
}

type Evaluator struct {
	loaderOptions []func(r *rego.Rego)
	policyData    map[string]interface{}
	opts          Options
}

// NewFromBundlePath loads the policy bundle at path, as the agent does.
func NewFromBundlePath(path string, policyData map[string]interface{}, opts Options) *Evaluator {
	return NewWithLoaders([]func(r *rego.Rego){rego.LoadBundle(path)}, policyData, opts)
}

// NewFromModules loads policies from source, keyed by file name. Nothing is read from disk.
func NewFromModules(modules map[string]string, policyData map[string]interface{}, opts Options) *Evaluator {
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)

	loaders := make([]func(r *rego.Rego), 0, len(names))
	for _, name := range names {
		loaders = append(loaders, rego.Module(name, modules[name]))
	}
	return NewWithLoaders(loaders, policyData, opts)
}

// NewWithLoaders uses caller-supplied rego loader options, for example rego.ParsedBundle.
func NewWithLoaders(loaders []func(r *rego.Rego), policyData map[string]interface{}, opts Options) *Evaluator {
	return &Evaluator{
		loaderOptions: loaders,
		policyData:    policyData,
		opts:          opts,
	}
}

// PrepareForEval compiles the loaded policies with regoArgs, writes the policy data into a
// fresh store, and applies the evaluator's options.
func (e *Evaluator) PrepareForEval(ctx context.Context, regoArgs ...func(r *rego.Rego)) (rego.PreparedEvalQuery, error) {
	store := inmem.New()
	txn, err := store.NewTransaction(ctx, storage.TransactionParams{Write: true})
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}

	committed := false
	defer func() {
		if !committed {
			store.Abort(ctx, txn)
		}
	}()

	args := make([]func(r *rego.Rego), 0, len(regoArgs)+len(e.loaderOptions)+5)
	args = append(args,
		rego.Store(store),
		rego.Transaction(txn),
	)
	args = append(args, e.optionArgs()...)
	args = append(args, regoArgs...)
	args = append(args, e.loaderOptions...)

	query, err := rego.New(args...).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}

	if err := writePolicyData(ctx, store, txn, e.policyData); err != nil {
		return rego.PreparedEvalQuery{}, err
	}

	if err := store.Commit(ctx, txn); err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	committed = true

	// PreparedEvalQuery.Eval opens a fresh read transaction unless an
	// EvalTransaction is provided, so committing this write transaction makes the
	// loaded bundle and injected policy data visible to later evaluations.
	return query, nil
}

func (e *Evaluator) optionArgs() []func(r *rego.Rego) {
	args := make([]func(r *rego.Rego), 0, 3)
	if e.opts.Capabilities != nil {
		args = append(args, rego.Capabilities(e.opts.Capabilities))
	}
	if e.opts.PrintHook != nil {
		args = append(args, rego.EnablePrintStatements(true), rego.PrintHook(e.opts.PrintHook))
	}
	return args
}

// EvalOptions returns the options to pass to PreparedEvalQuery.Eval. Prepared queries do
// not inherit rego.Time, so the pinned time is applied here.
func (e *Evaluator) EvalOptions() []rego.EvalOption {
	if e.opts.Time.IsZero() {
		return nil
	}
	return []rego.EvalOption{rego.EvalTime(e.opts.Time)}
}

func writePolicyData(ctx context.Context, store storage.Store, txn storage.Transaction, data map[string]interface{}) error {
	for key, value := range data {
		if err := writePolicyDataValue(ctx, store, txn, storage.Path{key}, value); err != nil {
			return err
		}
	}
	return nil
}

func writePolicyDataValue(ctx context.Context, store storage.Store, txn storage.Transaction, path storage.Path, value interface{}) error {
	valueMap, valueIsMap := value.(map[string]interface{})
	if valueIsMap {
		existing, err := store.Read(ctx, txn, path)
		if err == nil {
			if _, ok := existing.(map[string]interface{}); ok {
				for key, nestedValue := range valueMap {
					nestedPath := append(append(storage.Path{}, path...), key)
					if err := writePolicyDataValue(ctx, store, txn, nestedPath, nestedValue); err != nil {
						return err
					}
				}
				return nil
			}
		} else if !storage.IsNotFound(err) {
			return err
		}
	}

	op := storage.AddOp
	if _, err := store.Read(ctx, txn, path); err == nil {
		op = storage.ReplaceOp
	} else if !storage.IsNotFound(err) {
		return err
	}

	if err := store.Write(ctx, txn, op, path, value); err != nil {
		return fmt.Errorf("write policy data at %q: %w", path.String(), err)
	}
	return nil
}

// normalizeViolationEntries converts OPA's two possible serializations of a
// `violation` rule into a uniform list of JSON byte slices that can be decoded
// into a Violation via the same path.
//
// Partial object rule (`violation[obj] := ...` / `violation[obj]`): OPA returns
// a map[string]interface{} whose keys are JSON-encoded violation objects.
//
// Set rule (`violation contains {...}`): OPA returns a []interface{} whose
// elements are already-decoded violation objects.
func normalizeViolationEntries(val interface{}) ([][]byte, error) {
	switch v := val.(type) {
	case map[string]interface{}:
		entries := make([][]byte, 0, len(v))
		for key := range v {
			entries = append(entries, []byte(key))
		}
		return entries, nil
	case []interface{}:
		entries := make([][]byte, 0, len(v))
		for _, item := range v {
			raw, err := json.Marshal(item)
			if err != nil {
				return nil, fmt.Errorf("re-encode violation entry: %w", err)
			}
			entries = append(entries, raw)
		}
		return entries, nil
	default:
		return nil, fmt.Errorf("unexpected violations type %T, want map or slice", val)
	}
}

// Execute evaluates every package under data.compliance_framework against input.
func (e *Evaluator) Execute(ctx context.Context, input interface{}) ([]Result, error) {
	var output []Result

	query, err := e.PrepareForEval(ctx,
		rego.Query("data.compliance_framework"),
		rego.Package("compliance_framework"),
	)
	if err != nil {
		return nil, err
	}

	for _, module := range query.Modules() {
		// Exclude any test files for this compilation
		if strings.HasSuffix(module.Package.Location.File, "_test.rego") {
			continue
		}

		// Only treat packages under the compliance_framework namespace as
		// evaluable policies. Packages in other namespaces (e.g. shared helper
		// libraries under ccf_libs) are bundled for import only and must not be
		// evaluated as policies, as they intentionally produce no title/evidence.
		packagePath := module.Package.Path.String()
		if packagePath != "data.compliance_framework" && !strings.HasPrefix(packagePath, "data.compliance_framework.") {
			continue
		}

		result := Result{
			Policy: Policy{
				File:        module.Package.Location.File,
				Package:     Package(module.Package.Path.String()),
				Annotations: module.Annotations,
			},
		}

		subQuery, err := e.PrepareForEval(ctx,
			rego.Query(module.Package.Path.String()),
			rego.Package(module.Package.Path.String()),
			rego.Input(input),
		)
		if err != nil {
			return nil, err
		}

		evaluation, err := subQuery.Eval(ctx, e.EvalOptions()...)
		if err != nil {
			return nil, err
		}

		for _, eval := range evaluation {
			for _, expression := range eval.Expressions {
				moduleOutputs, ok := expression.Value.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf(
						"expected module outputs to be a map (policy package %q, file %q)",
						result.Policy.Package, result.Policy.File,
					)
				}
				violations := make([]Violation, 0)

				if val, ok := moduleOutputs["violation"]; ok {
					rawEntries, err := normalizeViolationEntries(val)
					if err != nil {
						return nil, fmt.Errorf(
							"%w (policy package %q, file %q)",
							err, result.Policy.Package, result.Policy.File,
						)
					}
					for _, raw := range rawEntries {
						viol := &Violation{}
						if err := json.Unmarshal(raw, viol); err != nil {
							return nil, fmt.Errorf(
								"decode violation entry (policy package %q, file %q): %w",
								result.Policy.Package, result.Policy.File, err,
							)
						}
						violations = append(violations, *viol)
					}
				}

				evalOutput := &EvalOutput{
					AdditionalVariables: map[string]interface{}{},
					Violations:          violations,
				}

				if err := mapstructure.Decode(moduleOutputs, evalOutput); err != nil {
					return nil, fmt.Errorf(
						"decode policy outputs (policy package %q, file %q): %w",
						result.Policy.Package, result.Policy.File, err,
					)
				}

				// TODO here we could run evalOutput.Validate()
				for key, value := range moduleOutputs {
					if !slices.Contains([]string{"violation", "labels"}, key) {
						evalOutput.AdditionalVariables[key] = value
					}
				}

				result.EvalOutput = evalOutput
				result.Raw = moduleOutputs
			}
		}
		output = append(output, result)
	}

	return output, nil
}
