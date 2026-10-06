package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schedulesValid and schedulesInvalid are shared with the conformance golden file
// (conformance_test.go). robfig/cron panics on the invalid time-zone prefixes; ParseSchedule
// must return an error instead.
var (
	schedulesValid   = []string{"TZ=UTC 0 * * * *", "CRON_TZ=Europe/London 0 * * * *", "*/5 * * * *", "@hourly"}
	schedulesInvalid = []string{"TZ=UTC", "CRON_TZ=UTC", "TZ=", "CRON_TZ="}
)

func TestParseScheduleTimeZonePrefix(t *testing.T) {
	for _, expr := range schedulesValid {
		_, err := ParseSchedule(expr)
		assert.NoError(t, err, expr)
	}
	for _, expr := range schedulesInvalid {
		require.NotPanics(t, func() {
			_, err := ParseSchedule(expr)
			assert.Error(t, err, expr)
		}, expr)
	}
	// The overlay rule O7 reports it as a validation error, not a crash.
	err := ValidateOverlay([]byte(`{"plugins":{"p":{"schedule":"TZ=UTC"}}}`))
	requireFieldError(t, err, "/plugins/p/schedule", FieldCodeCron)
}
