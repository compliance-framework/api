//go:build integration

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
)

// Regression (review #477/#481, fp f2b689648c35): a save validates against every fresh
// apply-mode instance, but instances that report the same base must not each be loaded and
// validated: the cost of a save follows the distinct bases, not the instance count.
func (s *AgentConfigAdminIntegrationSuite) TestRegressionSaveCostFollowsDistinctBases() {
	const (
		instances = 40
		baseBytes = 1 << 20 // 1 MiB reported base, shared by every instance
		// Budget for the whole PUT: a few copies of one base plus request overhead. Loading
		// and validating every instance's copy allocates well over instances*baseBytes.
		allocBudget = 32 << 20
	)
	schedule := "* * * * *"
	base, err := json.Marshal(agentconfig.Config{
		Daemon:       true,
		API:          &agentconfig.APIConfig{URL: "http://api:8080", Auth: &agentconfig.APIAuth{ClientID: uuid.NewString()}},
		RemoteConfig: &agentconfig.RemoteConfig{Mode: agentconfig.ModeApplySafe},
		Plugins: map[string]*agentconfig.Plugin{
			"ssh": {
				Source:   acaVendorPlugin,
				Schedule: &schedule,
				Policies: []string{acaVendorPolicy},
				Config:   map[string]string{"host": "localhost", "banner": strings.Repeat("b", baseBytes)},
			},
		},
	})
	s.Require().NoError(err)
	for i := 0; i < instances; i++ {
		s.report(*s.agent.ID, agentconfig.ModeApplySafe, func(r *agentconfig.Report) {
			r.Base = base
			r.Effective = base
		})
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	rec := s.put(s.server, s.token, `"0"`, `{"verbosity":1}`)
	runtime.ReadMemStats(&after)

	s.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	allocated := after.TotalAlloc - before.TotalAlloc
	s.LessOrEqual(allocated, uint64(allocBudget),
		fmt.Sprintf("PUT allocated %d MiB for %d instances sharing one %d MiB base", allocated>>20, instances, baseBytes>>20))
}
