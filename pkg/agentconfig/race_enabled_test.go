//go:build race

package agentconfig

// raceEnabled reports whether the tests run under the race detector, which slows tight loops
// by roughly an order of magnitude. Timing budgets scale with it (see timeBudget).
const raceEnabled = true
