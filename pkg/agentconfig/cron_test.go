package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScheduleTimeZonePrefix(t *testing.T) {
	for _, expr := range []string{"TZ=UTC 0 * * * *", "CRON_TZ=Europe/London 0 * * * *"} {
		_, err := ParseSchedule(expr)
		assert.NoError(t, err, expr)
	}
	// robfig/cron panics on these; ParseSchedule must return an error instead.
	for _, expr := range []string{"TZ=UTC", "CRON_TZ=UTC", "TZ=", "CRON_TZ="} {
		require.NotPanics(t, func() {
			_, err := ParseSchedule(expr)
			assert.Error(t, err, expr)
		}, expr)
	}
	// The overlay rule O7 reports it as a validation error, not a crash.
	err := ValidateOverlay([]byte(`{"plugins":{"p":{"schedule":"TZ=UTC"}}}`))
	requireFieldError(t, err, "/plugins/p/schedule", FieldCodeCron)
}
