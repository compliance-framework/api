//go:build !race

package agentconfig

// raceEnabled reports whether the tests run under the race detector (see race_enabled_test.go).
const raceEnabled = false
