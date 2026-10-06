package agentconfig

import "time"

// raceSlowdown is how much a wall-clock budget grows under the race detector.
const raceSlowdown = 10

// timeBudget scales a wall-clock budget for the instrumentation in use, so a linearity check
// keeps failing on quadratic behaviour without failing on a slower, instrumented build.
func timeBudget(d time.Duration) time.Duration {
	if raceEnabled {
		return d * raceSlowdown
	}
	return d
}
