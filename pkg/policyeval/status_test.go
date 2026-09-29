package policyeval

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatus(t *testing.T) {
	violation := Violation{ID: pointer("v1")}

	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{
			name:   "no violations is satisfied",
			result: Result{EvalOutput: &EvalOutput{}},
			want:   StatusSatisfied,
		},
		{
			name:   "any violation is not satisfied",
			result: Result{EvalOutput: &EvalOutput{Violations: []Violation{violation}}},
			want:   StatusNotSatisfied,
		},
		{
			name:   "non-empty skip reason is skipped, even with violations",
			result: Result{EvalOutput: &EvalOutput{SkipReason: pointer("bad input"), Violations: []Violation{violation}}},
			want:   StatusSkipped,
		},
		{
			name:   "empty skip reason is ignored",
			result: Result{EvalOutput: &EvalOutput{SkipReason: pointer("")}},
			want:   StatusSatisfied,
		},
		{
			name:   "no output is not satisfied",
			result: Result{},
			want:   StatusNotSatisfied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Status(tt.result))
		})
	}
}
