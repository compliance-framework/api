//go:build integration

package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/suite"
)

type AgentInstancePruneWorkerIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestAgentInstancePruneWorkerIntegrationSuite(t *testing.T) {
	suite.Run(t, new(AgentInstancePruneWorkerIntegrationSuite))
}

func (s *AgentInstancePruneWorkerIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
}

func (s *AgentInstancePruneWorkerIntegrationSuite) insert(agentID uuid.UUID, daemon *bool, lastSeen time.Time) uuid.UUID {
	id := uuid.New()
	s.Require().NoError(s.DB.Create(&relational.AgentInstance{
		AgentID: agentID, InstanceID: id, Daemon: daemon,
		FirstSeenAt: lastSeen, LastSeenAt: lastSeen, CreatedAt: lastSeen, UpdatedAt: lastSeen,
	}).Error)
	return id
}

func (s *AgentInstancePruneWorkerIntegrationSuite) remaining() map[uuid.UUID]bool {
	var rows []relational.AgentInstance
	s.Require().NoError(s.DB.Find(&rows).Error)
	out := map[uuid.UUID]bool{}
	for _, r := range rows {
		out[r.InstanceID] = true
	}
	return out
}

func (s *AgentInstancePruneWorkerIntegrationSuite) TestWorkPrunesWithDefaultRetention() {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	agent, err := s.CreateAgent("prune-worker")
	s.Require().NoError(err)
	f, tr := false, true
	oneShotOld := s.insert(*agent.ID, &f, now.Add(-25*time.Hour))
	oneShotNew := s.insert(*agent.ID, &f, now.Add(-time.Hour))
	daemon25h := s.insert(*agent.ID, &tr, now.Add(-25*time.Hour))
	daemonOld := s.insert(*agent.ID, &tr, now.Add(-721*time.Hour))
	unknown25h := s.insert(*agent.ID, nil, now.Add(-25*time.Hour))

	w := NewAgentInstancePruneWorker(s.DB, agentcfg.Settings{}, nil)
	w.now = func() time.Time { return now }
	s.Require().NoError(w.Work(context.Background(), &river.Job[AgentInstancePruneArgs]{}))

	left := s.remaining()
	s.Len(left, 3)
	s.False(left[oneShotOld])
	s.True(left[oneShotNew])
	s.True(left[daemon25h])
	s.False(left[daemonOld])
	s.True(left[unknown25h])

	// A second run is a no-op.
	s.Require().NoError(w.Work(context.Background(), &river.Job[AgentInstancePruneArgs]{}))
	s.Len(s.remaining(), 3)
}

func (s *AgentInstancePruneWorkerIntegrationSuite) TestWorkHonoursConfiguredRetention() {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	agent, err := s.CreateAgent("prune-worker-custom")
	s.Require().NoError(err)
	f, tr := false, true
	oneShot := s.insert(*agent.ID, &f, now.Add(-2*time.Hour))
	daemon := s.insert(*agent.ID, &tr, now.Add(-49*time.Hour))
	daemonKept := s.insert(*agent.ID, &tr, now.Add(-47*time.Hour))

	w := NewAgentInstancePruneWorker(s.DB, agentcfg.Settings{OneShotInstanceRetention: time.Hour, InstanceRetention: 48 * time.Hour}, nil)
	w.now = func() time.Time { return now }
	s.Require().NoError(w.Work(context.Background(), &river.Job[AgentInstancePruneArgs]{}))

	left := s.remaining()
	s.False(left[oneShot])
	s.False(left[daemon])
	s.True(left[daemonKept])
}
