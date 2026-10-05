//go:build integration

package agentcfg_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type AgentCfgServiceIntegrationSuite struct {
	tests.IntegrationTestSuite
	ctx context.Context
	now time.Time
	svc *agentcfg.Service
}

func TestAgentCfgServiceIntegration(t *testing.T) {
	suite.Run(t, new(AgentCfgServiceIntegrationSuite))
}

func (s *AgentCfgServiceIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
	s.ctx = context.Background()
	s.now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s.svc = s.newService(agentcfg.Settings{})
}

// newService builds a service whose clock follows s.now.
func (s *AgentCfgServiceIntegrationSuite) newService(settings agentcfg.Settings) *agentcfg.Service {
	svc := agentcfg.NewService(s.DB, settings, nil)
	svc.SetClock(func() time.Time { return s.now })
	return svc
}

func (s *AgentCfgServiceIntegrationSuite) newAgent(name string) uuid.UUID {
	agent, err := s.CreateAgent(name)
	s.Require().NoError(err)
	return *agent.ID
}

func (s *AgentCfgServiceIntegrationSuite) createRevision(agentID uuid.UUID, expected int64, overlay string) *relational.AgentConfigRevision {
	rev, err := s.svc.CreateRevision(s.ctx, agentcfg.CreateRevisionParams{
		AgentID:          agentID,
		ExpectedRevision: expected,
		Overlay:          json.RawMessage(overlay),
		CreatedBy:        "alice@example.com",
	})
	s.Require().NoError(err)
	return rev
}

func ptr[T any](v T) *T { return &v }

// ---- Revisions ----

func (s *AgentCfgServiceIntegrationSuite) TestRevisionHooksAreAppendOnly() {
	agentID := s.newAgent("hooks")
	rev := s.createRevision(agentID, 0, `{"verbosity":1}`)

	err := s.DB.Model(rev).Update("comment", "changed").Error
	s.ErrorIs(err, relational.ErrAgentConfigRevisionAppendOnly)

	rev.CreatedBy = "mallory@example.com"
	s.ErrorIs(s.DB.Save(rev).Error, relational.ErrAgentConfigRevisionAppendOnly)

	s.ErrorIs(s.DB.Delete(rev).Error, relational.ErrAgentConfigRevisionAppendOnly)
	s.ErrorIs(s.DB.Where("agent_id = ?", agentID).Delete(&relational.AgentConfigRevision{}).Error,
		relational.ErrAgentConfigRevisionAppendOnly)

	stored, err := s.svc.GetRevision(s.ctx, agentID, 1)
	s.Require().NoError(err)
	s.Nil(stored.Comment)
	s.Equal("alice@example.com", stored.CreatedBy)
}

func (s *AgentCfgServiceIntegrationSuite) TestRevisionUniqueIndex() {
	agentA := s.newAgent("unique-a")
	agentB := s.newAgent("unique-b")
	mk := func(agentID uuid.UUID, rev int64) *relational.AgentConfigRevision {
		return &relational.AgentConfigRevision{
			AgentID: agentID, Revision: rev, Overlay: datatypes.JSON(`{}`), CreatedBy: "a", CreatedAt: s.now,
		}
	}
	s.Require().NoError(s.DB.Create(mk(agentA, 1)).Error)
	s.Error(s.DB.Create(mk(agentA, 1)).Error, "(agent_id, revision) must be unique")
	s.NoError(s.DB.Create(mk(agentB, 1)).Error, "the same revision number is fine for another agent")
	s.NoError(s.DB.Create(mk(agentA, 2)).Error)
}

func (s *AgentCfgServiceIntegrationSuite) TestCreateRevisionSequenceAndConflicts() {
	agentID := s.newAgent("seq")

	cur, err := s.svc.Current(s.ctx, agentID)
	s.Require().NoError(err)
	s.Nil(cur, "no revision yet means revision 0")
	n, err := s.svc.CurrentRevisionNumber(s.ctx, agentID)
	s.Require().NoError(err)
	s.Equal(int64(0), n)

	userID := uuid.New()
	rev1, err := s.svc.CreateRevision(s.ctx, agentcfg.CreateRevisionParams{
		AgentID: agentID, ExpectedRevision: 0, Overlay: json.RawMessage(`{"verbosity":1}`),
		Comment: ptr("first"), CreatedBy: "alice@example.com", CreatedByID: &userID,
	})
	s.Require().NoError(err)
	s.Equal(int64(1), rev1.Revision)
	s.NotNil(rev1.ID)
	s.True(rev1.CreatedAt.Equal(s.now))

	s.now = s.now.Add(time.Minute)
	rev2, err := s.svc.CreateRevision(s.ctx, agentcfg.CreateRevisionParams{
		AgentID: agentID, ExpectedRevision: 1, Overlay: json.RawMessage(`{"verbosity":2}`),
		CreatedBy: "bob@example.com", RevertOf: ptr(int64(1)),
	})
	s.Require().NoError(err)
	s.Equal(int64(2), rev2.Revision)
	s.NotEqual(*rev1.ID, *rev2.ID)

	for _, expected := range []int64{0, 1, 5} {
		_, err = s.svc.CreateRevision(s.ctx, agentcfg.CreateRevisionParams{
			AgentID: agentID, ExpectedRevision: expected, Overlay: json.RawMessage(`{}`), CreatedBy: "x",
		})
		s.Require().Error(err)
		s.True(errors.Is(err, agentcfg.ErrRevisionConflict), "expected %d", expected)
		var conflict *agentcfg.RevisionConflictError
		s.Require().True(errors.As(err, &conflict))
		s.Equal(int64(2), conflict.Current)
	}

	_, err = s.svc.CreateRevision(s.ctx, agentcfg.CreateRevisionParams{
		AgentID: uuid.New(), ExpectedRevision: 0, Overlay: json.RawMessage(`{}`), CreatedBy: "x",
	})
	s.ErrorIs(err, agentcfg.ErrNotFound)

	cur, err = s.svc.Current(s.ctx, agentID)
	s.Require().NoError(err)
	s.Require().NotNil(cur)
	s.Equal(int64(2), cur.Revision)
	s.JSONEq(`{"verbosity":2}`, string(cur.Overlay))
	s.Equal("bob@example.com", cur.CreatedBy)
	s.Require().NotNil(cur.RevertOf)
	s.Equal(int64(1), *cur.RevertOf)

	n, err = s.svc.CurrentRevisionNumber(s.ctx, agentID)
	s.Require().NoError(err)
	s.Equal(int64(2), n)

	got, err := s.svc.GetRevision(s.ctx, agentID, 1)
	s.Require().NoError(err)
	s.JSONEq(`{"verbosity":1}`, string(got.Overlay))
	s.Equal("first", *got.Comment)
	s.Equal(userID, *got.CreatedByID)
	s.True(got.CreatedAt.Equal(rev1.CreatedAt))

	_, err = s.svc.GetRevision(s.ctx, agentID, 3)
	s.ErrorIs(err, agentcfg.ErrNotFound)
	other := s.newAgent("seq-other")
	_, err = s.svc.GetRevision(s.ctx, other, 1)
	s.ErrorIs(err, agentcfg.ErrNotFound)
}

func (s *AgentCfgServiceIntegrationSuite) TestCreateRevisionConcurrentWritersExactlyOneWins() {
	for round := 0; round < 5; round++ {
		agentID := s.newAgent("concurrent")
		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, errs[i] = s.svc.CreateRevision(s.ctx, agentcfg.CreateRevisionParams{
					AgentID: agentID, ExpectedRevision: 0, Overlay: json.RawMessage(`{"verbosity":1}`), CreatedBy: "x",
				})
			}(i)
		}
		close(start)
		wg.Wait()

		var ok, conflicts int
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, agentcfg.ErrRevisionConflict):
				conflicts++
				var conflict *agentcfg.RevisionConflictError
				s.Require().True(errors.As(err, &conflict))
				s.Equal(int64(1), conflict.Current)
			default:
				s.Failf("unexpected error", "%v", err)
			}
		}
		s.Equal(1, ok, "round %d", round)
		s.Equal(1, conflicts, "round %d", round)
		n, err := s.svc.CurrentRevisionNumber(s.ctx, agentID)
		s.Require().NoError(err)
		s.Equal(int64(1), n)
	}
}

func (s *AgentCfgServiceIntegrationSuite) TestListRevisionsPagesNewestFirst() {
	agentID := s.newAgent("list")
	other := s.newAgent("list-other")
	for i := int64(0); i < 5; i++ {
		s.now = s.now.Add(time.Minute)
		_, err := s.svc.CreateRevision(s.ctx, agentcfg.CreateRevisionParams{
			AgentID: agentID, ExpectedRevision: i, Overlay: json.RawMessage(`{"verbosity":1,"plugins":{"p":{"source":"x"}}}`),
			Comment: ptr("c"), CreatedBy: "alice@example.com", RevertOf: ptr(int64(1)),
		})
		s.Require().NoError(err)
	}
	s.createRevision(other, 0, `{}`)

	page, total, err := s.svc.ListRevisions(s.ctx, agentID, service.PaginationParams{Page: 1, Limit: 2, Offset: 0})
	s.Require().NoError(err)
	s.Equal(int64(5), total)
	s.Require().Len(page, 2)
	s.Equal(int64(5), page[0].Revision)
	s.Equal(int64(4), page[1].Revision)
	for _, m := range page {
		s.NotEqual(uuid.Nil, m.ID)
		s.Equal(agentID, m.AgentID)
		s.Greater(m.OverlaySize, 0)
		s.Equal("alice@example.com", m.CreatedBy)
		s.Require().NotNil(m.Comment)
		s.Equal("c", *m.Comment)
		s.Require().NotNil(m.RevertOf)
		s.False(m.CreatedAt.IsZero())
	}
	s.True(page[0].CreatedAt.After(page[1].CreatedAt))

	page, total, err = s.svc.ListRevisions(s.ctx, agentID, service.PaginationParams{Page: 3, Limit: 2, Offset: 4})
	s.Require().NoError(err)
	s.Equal(int64(5), total)
	s.Require().Len(page, 1)
	s.Equal(int64(1), page[0].Revision)

	page, total, err = s.svc.ListRevisions(s.ctx, s.newAgent("list-empty"), service.PaginationParams{Page: 1, Limit: 10})
	s.Require().NoError(err)
	s.Equal(int64(0), total)
	s.Empty(page)
}

// ---- Instances ----

func (s *AgentCfgServiceIntegrationSuite) TestDeleteRevisionsForAgent() {
	agentA := s.newAgent("purge-a")
	agentB := s.newAgent("purge-b")
	s.createRevision(agentA, 0, `{"plugins":{"p":{"config":{"password":"hunter2"}}}}`)
	s.createRevision(agentA, 1, `{"verbosity":2}`)
	s.createRevision(agentB, 0, `{"verbosity":1}`)

	s.Require().NoError(s.DB.Transaction(func(tx *gorm.DB) error {
		return agentcfg.DeleteRevisionsForAgent(tx, agentA)
	}))

	var n int64
	s.Require().NoError(s.DB.Model(&relational.AgentConfigRevision{}).Where("agent_id = ?", agentA).Count(&n).Error)
	s.Zero(n, "every revision of the agent is purged")
	cur, err := s.svc.CurrentRevisionNumber(s.ctx, agentB)
	s.Require().NoError(err)
	s.Equal(int64(1), cur, "other agents keep theirs")

	// Every other delete path stays append-only.
	s.ErrorIs(s.DB.Where("agent_id = ?", agentB).Delete(&relational.AgentConfigRevision{}).Error,
		relational.ErrAgentConfigRevisionAppendOnly)
}

func (s *AgentCfgServiceIntegrationSuite) TestCreateRevisionReturnsTheStoredRow() {
	agentID := s.newAgent("stored")
	rev := s.createRevision(agentID, 0, `{"verbosity":1,"plugins":{"b":{"enabled":false},"a":{"enabled":true}}}`)
	got, err := s.svc.GetRevision(s.ctx, agentID, rev.Revision)
	s.Require().NoError(err)
	s.Equal(string(got.Overlay), string(rev.Overlay), "same bytes as a later read")
	s.Equal(*got.ID, *rev.ID)

	metas, _, err := s.svc.ListRevisions(s.ctx, agentID, service.PaginationParams{Page: 1, Limit: 10})
	s.Require().NoError(err)
	s.Require().Len(metas, 1)
	s.Equal(len(rev.Overlay), metas[0].OverlaySize)
}
