package policyeval

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// EvalOutput is the decoded value of one compliance_framework policy package.
type EvalOutput struct {
	Title               *string            `mapstructure:"title,omitempty"`
	Description         *string            `mapstructure:"description,omitempty"`
	Remarks             *string            `mapstructure:"remarks,omitempty"`
	SkipReason          *string            `mapstructure:"skip_reason,omitempty"`
	Labels              *map[string]string `mapstructure:"labels,omitempty"`
	Violations          []Violation
	AdditionalVariables map[string]interface{}
}

type Violation struct {
	ID          *string `json:"id,omitempty" mapstructure:"id"`
	Title       *string `json:"title,omitempty" mapstructure:"title"`
	Description *string `json:"description,omitempty" mapstructure:"description"`
	Remarks     *string `json:"remarks,omitempty" mapstructure:"remarks"`
}

type Package string

func (p Package) PurePackage() string {
	return strings.TrimPrefix(string(p), "data.")
}

type Policy struct {
	File        string
	Package     Package
	Annotations []*ast.Annotations
	// ID is the module's policy_id (R74): set only when the package's output has a
	// policy_id that ValidPolicyID accepts. SeedPath turns it into evidence seed values.
	ID string `json:"id,omitempty"`
}

type Result struct {
	Policy Policy
	*EvalOutput
	// Raw is the package's full value as returned by OPA, before decoding.
	Raw map[string]interface{}
	// Issues are the policy contract problems ValidateResult found in this result. They do
	// not stop evaluation; callers decide whether they matter.
	Issues []Issue
}

func (res Result) String() string {
	return fmt.Sprintf(`
Policy:
	file: %s
	package: %s
	annotations: %s
AdditionalVariables: %v
Labels: %v
Violations: %v
`, res.Policy.File, res.Policy.Package.PurePackage(), res.Policy.Annotations, res.AdditionalVariables, res.Labels, res.Violations)
}
