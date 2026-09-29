package policyeval

const (
	StatusSatisfied    = "satisfied"
	StatusNotSatisfied = "not-satisfied"
	StatusSkipped      = "skipped"
)

// Status applies the agent's GenerateResults rule: a non-empty skip_reason means the
// result produces no evidence; otherwise no violations is satisfied and any violation is
// not satisfied.
func Status(result Result) string {
	if result.EvalOutput == nil {
		return StatusNotSatisfied
	}
	if result.SkipReason != nil && *result.SkipReason != "" {
		return StatusSkipped
	}
	if len(result.Violations) > 0 {
		return StatusNotSatisfied
	}
	return StatusSatisfied
}
