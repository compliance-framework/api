package templates

import (
	"testing"

	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/pkg/risktemplate"
	"github.com/stretchr/testify/assert"
)

// TestRiskTemplateHintParity pins pkg/risktemplate's hint rule, which the policy contract
// checker uses, to the rule this service enforces on save.
func TestRiskTemplateHintParity(t *testing.T) {
	values := []string{"", " ", "low", "LOW", " moderate ", "medium", "high", "critical", "negligible", "severe", "5", "{{ .level }}", "none"}
	for _, level := range []riskrel.RiskLevel{riskrel.RiskLevelNegligible, riskrel.RiskLevelLow, riskrel.RiskLevelModerate, riskrel.RiskLevelHigh, riskrel.RiskLevelCritical, riskrel.RiskLevelMediumLegacy} {
		values = append(values, string(level))
	}
	for _, value := range values {
		v := value
		serviceAccepts := validateOptionalTemplateRiskLevel("likelihoodHint", &v) == nil
		assert.Equal(t, serviceAccepts, risktemplate.ValidHint(value), "%q", value)
	}
}
