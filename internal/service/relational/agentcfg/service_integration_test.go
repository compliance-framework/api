//go:build integration

package agentcfg_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/compliance-framework/api/pkg/agentconfig"
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

// insertInstance writes an instance row directly (bypassing the cap), seen at lastSeen.
func (s *AgentCfgServiceIntegrationSuite) insertInstance(agentID uuid.UUID, daemon *bool, lastSeen time.Time) uuid.UUID {
	instanceID := uuid.New()
	row := &relational.AgentInstance{
		AgentID:     agentID,
		InstanceID:  instanceID,
		Mode:        agentconfig.ModeApplySafe,
		Daemon:      daemon,
		FirstSeenAt: lastSeen,
		LastSeenAt:  lastSeen,
		CreatedAt:   lastSeen,
		UpdatedAt:   lastSeen,
	}
	s.Require().NoError(s.DB.Create(row).Error)
	return instanceID
}

// deleteOneInstance deletes one (any) instance row of an agent.
func (s *AgentCfgServiceIntegrationSuite) deleteOneInstance(agentID uuid.UUID) {
	var victim relational.AgentInstance
	s.Require().NoError(s.DB.Where("agent_id = ?", agentID).First(&victim).Error)
	s.Require().NoError(s.DB.Delete(&victim).Error)
}

func (s *AgentCfgServiceIntegrationSuite) countInstances(agentID uuid.UUID) int64 {
	var n int64
	s.Require().NoError(s.DB.Model(&relational.AgentInstance{}).Where("agent_id = ?", agentID).Count(&n).Error)
	return n
}

// reportAt stores a report with the service clock set to at, then restores the clock.
func (s *AgentCfgServiceIntegrationSuite) reportAt(svc *agentcfg.Service, at time.Time, agentID, instanceID uuid.UUID, r agentconfig.Report) error {
	saved := s.now
	s.now = at
	defer func() { s.now = saved }()
	return svc.UpsertReport(s.ctx, agentID, nil, instanceID, r)
}

func applyReport(mode string, base string) agentconfig.Report {
	r := agentconfig.Report{
		Mode:            mode,
		Daemon:          true,
		AppliedRevision: ptr(int64(1)),
		Status:          agentconfig.StatusApplied,
		EffectiveDigest: "sha256:abc",
	}
	if base != "" {
		r.Base = json.RawMessage(base)
		r.Effective = json.RawMessage(base)
	}
	return r
}

func ptr[T any](v T) *T { return &v }

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

const baseConfig = `{"daemon":true,"verbosity":0,"api":{"url":"http://api:8080","auth":{"client_id":"cid"}},"plugins":{"p1":{"source":"ghcr.io/x/p1:v1","policies":["ghcr.io/x/pol:v1"]}}}`

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

func (s *AgentCfgServiceIntegrationSuite) TestUpsertReportInsertsThenUpdates() {
	agentID := s.newAgent("report")
	instanceID := uuid.New()
	credID := uuid.New()
	t0 := s.now

	warnings := []agentconfig.FieldError{{Path: "/plugins/p1/foo", Code: "unknown-field", Message: "unknown"}}
	plugins := []agentconfig.PluginReport{{Name: "p1", Source: "ghcr.io/x/p1:v1", LibVersion: "v0.7.1"}}
	unsafe := []agentconfig.Change{{Path: "/plugins/p1/source", Safety: agentconfig.Unsafe, Reason: "source-changed"}}
	remote := &agentconfig.RemoteConfig{Mode: agentconfig.ModeApplyAll, PollInterval: "30s", TrustedSources: []string{"ghcr.io/x/*"}}
	effective := `{"daemon":true,"verbosity":1,"plugins":{}}`

	err := s.svc.UpsertReport(s.ctx, agentID, &credID, instanceID, agentconfig.Report{
		Hostname: "  host-1  ", AgentVersion: "v1.2.3", Mode: agentconfig.ModeApplyAll, Daemon: true,
		AppliedRevision: ptr(int64(1)), AttemptedRevision: ptr(int64(2)), Status: agentconfig.StatusFailed,
		Reason: agentconfig.ReasonDownloadFailed, Error: ptr("oci pull failed"), Truncated: true,
		Warnings: warnings, Base: json.RawMessage(baseConfig), Effective: json.RawMessage(effective),
		EffectiveDigest: "sha256:eff", Unsafe: unsafe,
		RemoteConfig: remote, Plugins: plugins,
	})
	s.Require().NoError(err)

	got, err := s.svc.GetInstance(s.ctx, agentID, instanceID)
	s.Require().NoError(err)
	firstID := *got.ID
	s.Equal(credID, *got.CredentialID)
	s.Equal("host-1", *got.Hostname)
	s.Equal("v1.2.3", *got.AgentVersion)
	s.Equal(agentconfig.ModeApplyAll, got.Mode)
	s.Require().NotNil(got.Daemon)
	s.True(*got.Daemon)
	s.Equal(int64(1), *got.AppliedRevision)
	s.Equal(int64(2), *got.AttemptedRevision)
	s.Equal(agentconfig.StatusFailed, got.ReportedStatus)
	s.Equal(agentconfig.ReasonDownloadFailed, *got.ApplyReason)
	s.Equal("oci pull failed", *got.ApplyError)
	s.True(got.Truncated)
	s.JSONEq(mustJSON(warnings), string(got.Warnings))
	s.JSONEq(baseConfig, string(got.BaseConfig))
	s.JSONEq(effective, string(got.EffectiveConfig))
	s.Equal("sha256:eff", *got.EffectiveDigest)
	s.JSONEq(mustJSON(remote), string(got.RemoteConfig))
	s.JSONEq(mustJSON(unsafe), string(got.UnsafeChanges))
	s.JSONEq(mustJSON(plugins), string(got.Plugins))
	s.True(got.FirstSeenAt.Equal(t0))
	s.True(got.LastSeenAt.Equal(t0))
	s.Require().NotNil(got.ReportedAt)
	s.True(got.ReportedAt.Equal(t0))
	s.Nil(got.HeartbeatConfigDigest)

	// Second report from the same instance updates the same row.
	t1 := t0.Add(5 * time.Minute)
	s.now = t1
	err = s.svc.UpsertReport(s.ctx, agentID, &credID, instanceID, agentconfig.Report{
		Mode: agentconfig.ModeApplySafe, Daemon: false, AppliedRevision: ptr(int64(2)),
		Status: agentconfig.StatusApplied, Base: json.RawMessage(baseConfig), EffectiveDigest: "sha256:eff2",
	})
	s.Require().NoError(err)
	s.Equal(int64(1), s.countInstances(agentID))

	got, err = s.svc.GetInstance(s.ctx, agentID, instanceID)
	s.Require().NoError(err)
	s.Equal(firstID, *got.ID)
	s.True(got.FirstSeenAt.Equal(t0), "first_seen_at is kept")
	s.True(got.LastSeenAt.Equal(t1))
	s.True(got.ReportedAt.Equal(t1))
	s.Equal(agentconfig.ModeApplySafe, got.Mode)
	s.False(*got.Daemon)
	s.Equal(int64(2), *got.AppliedRevision)
	s.Nil(got.AttemptedRevision)
	s.Equal(agentconfig.StatusApplied, got.ReportedStatus)
	s.Nil(got.ApplyReason)
	s.Nil(got.ApplyError)
	s.Nil(got.Hostname)
	s.False(got.Truncated)
	s.Nil(got.Warnings)
	s.Nil(got.EffectiveConfig)
	s.Nil(got.RemoteConfig)
	s.Nil(got.UnsafeChanges)
	s.Nil(got.Plugins)
	s.Equal("sha256:eff2", *got.EffectiveDigest)
}

func (s *AgentCfgServiceIntegrationSuite) TestInstanceCapCountsOnlyNonPrunableRows() {
	svc := s.newService(agentcfg.Settings{MaxInstancesPerAgent: 2})
	report := applyReport(agentconfig.ModeApplySafe, baseConfig)

	agentA := s.newAgent("cap-a")
	i1, i2 := uuid.New(), uuid.New()
	s.Require().NoError(svc.UpsertReport(s.ctx, agentA, nil, i1, report))
	s.Require().NoError(svc.UpsertReport(s.ctx, agentA, nil, i2, report))
	err := svc.UpsertReport(s.ctx, agentA, nil, uuid.New(), report)
	s.ErrorIs(err, agentcfg.ErrInstanceLimit, "every counted instance is fresh: nothing to replace")
	s.Equal(int64(2), s.countInstances(agentA))
	s.NoError(svc.UpsertReport(s.ctx, agentA, nil, i1, report), "an existing instance can still report")
	s.NoError(svc.UpsertReport(s.ctx, s.newAgent("cap-other"), nil, uuid.New(), report), "the cap is per agent")

	// Prune-eligible rows do not count toward the cap (and are never evicted).
	agentB := s.newAgent("cap-b")
	s.insertInstance(agentB, ptr(false), s.now.Add(-25*time.Hour))  // one-shot, older than 24h
	s.insertInstance(agentB, ptr(true), s.now.Add(-721*time.Hour))  // daemon, older than 720h
	s.insertInstance(agentB, nil, s.now.Add(-800*time.Hour))        // unknown, older than 720h
	s.insertInstance(agentB, ptr(false), s.now.Add(-721*time.Hour)) // both
	s.Require().NoError(svc.UpsertReport(s.ctx, agentB, nil, uuid.New(), report))
	s.Require().NoError(svc.UpsertReport(s.ctx, agentB, nil, uuid.New(), report))
	s.ErrorIs(svc.UpsertReport(s.ctx, agentB, nil, uuid.New(), report), agentcfg.ErrInstanceLimit)
	s.Equal(int64(6), s.countInstances(agentB))

	// Non-prunable fresh rows count: a one-shot or an unknown (daemon NULL) instance seen
	// within InstanceStaleAfter (10m by default).
	agentC := s.newAgent("cap-c")
	s.insertInstance(agentC, ptr(false), s.now.Add(-time.Minute))
	s.insertInstance(agentC, nil, s.now.Add(-10*time.Minute)) // exactly at the threshold: fresh
	s.ErrorIs(svc.UpsertReport(s.ctx, agentC, nil, uuid.New(), report), agentcfg.ErrInstanceLimit)

	s.ErrorIs(svc.UpsertReport(s.ctx, uuid.New(), nil, uuid.New(), report), agentcfg.ErrNotFound)
}

// At the cap, a new instance replaces the oldest stale counted instance (e.g. a restarted
// DaemonSet's old instance ids), so the counted rows never exceed the cap.
func (s *AgentCfgServiceIntegrationSuite) TestInstanceCapReplacesOldestStaleInstance() {
	svc := s.newService(agentcfg.Settings{MaxInstancesPerAgent: 3})
	report := applyReport(agentconfig.ModeApplySafe, baseConfig)
	agentID := s.newAgent("cap-evict")
	instanceExists := func(id uuid.UUID) bool {
		_, err := svc.GetInstance(s.ctx, agentID, id)
		if errors.Is(err, agentcfg.ErrNotFound) {
			return false
		}
		s.Require().NoError(err)
		return true
	}

	fresh := s.insertInstance(agentID, ptr(true), s.now.Add(-time.Minute))
	older := s.insertInstance(agentID, ptr(true), s.now.Add(-2*time.Hour))
	oldest := s.insertInstance(agentID, nil, s.now.Add(-100*time.Hour))
	prunable := s.insertInstance(agentID, ptr(false), s.now.Add(-48*time.Hour)) // not counted, never evicted

	// A report from a new instance replaces the oldest stale counted row.
	r1 := uuid.New()
	s.Require().NoError(svc.UpsertReport(s.ctx, agentID, nil, r1, report))
	s.True(instanceExists(r1))
	s.False(instanceExists(oldest), "the oldest stale instance is replaced")
	s.True(instanceExists(older))
	s.True(instanceExists(prunable), "prune-eligible rows are left to the prune job")
	s.Equal(int64(4), s.countInstances(agentID))

	// A heartbeat from a new instance does the same.
	h1 := uuid.New()
	s.Require().NoError(svc.TouchFromHeartbeat(s.ctx, agentID, nil, h1, nil, ptr("sha256:hb")))
	s.True(instanceExists(h1))
	s.False(instanceExists(older))
	s.True(instanceExists(fresh))
	s.Equal(int64(4), s.countInstances(agentID))

	// Now every counted instance is fresh: reports get ErrInstanceLimit, heartbeats are
	// skipped, and nothing is deleted.
	s.ErrorIs(svc.UpsertReport(s.ctx, agentID, nil, uuid.New(), report), agentcfg.ErrInstanceLimit)
	s.NoError(svc.TouchFromHeartbeat(s.ctx, agentID, nil, uuid.New(), nil, ptr("sha256:hb")))
	s.Equal(int64(4), s.countInstances(agentID))
	s.True(instanceExists(fresh))
	s.True(instanceExists(r1))
	s.True(instanceExists(h1))

	// Many new instances in a row never grow the counted rows past the cap.
	s.now = s.now.Add(time.Hour) // every row is stale now
	for i := 0; i < 10; i++ {
		s.Require().NoError(svc.UpsertReport(s.ctx, agentID, nil, uuid.New(), report))
		s.now = s.now.Add(11 * time.Minute)
	}
	var counted int64
	s.Require().NoError(s.DB.Model(&relational.AgentInstance{}).
		Where("agent_id = ? AND (daemon IS NULL OR daemon = true)", agentID).Count(&counted).Error)
	s.Equal(int64(3), counted)
}

// Once the cap is found reached, heartbeats from new instances skip the insert path (no
// locked count) for capReachedTTL (1m); reports always check the cap.
func (s *AgentCfgServiceIntegrationSuite) TestHeartbeatCapReachedIsCached() {
	svc := s.newService(agentcfg.Settings{MaxInstancesPerAgent: 2})
	agentID := s.newAgent("cap-cache")
	digest := ptr("sha256:hb")
	s.insertInstance(agentID, ptr(true), s.now)
	freed := s.insertInstance(agentID, ptr(true), s.now)

	s.NoError(svc.TouchFromHeartbeat(s.ctx, agentID, nil, uuid.New(), nil, digest))
	s.Equal(int64(2), s.countInstances(agentID))

	// A slot frees up, but within the TTL a new heartbeating instance is still skipped.
	s.Require().NoError(s.DB.Where("agent_id = ? AND instance_id = ?", agentID, freed).Delete(&relational.AgentInstance{}).Error)
	s.now = s.now.Add(30 * time.Second)
	s.NoError(svc.TouchFromHeartbeat(s.ctx, agentID, nil, uuid.New(), nil, digest))
	s.Equal(int64(1), s.countInstances(agentID))

	// Other agents are not affected.
	other := s.newAgent("cap-cache-other")
	s.NoError(svc.TouchFromHeartbeat(s.ctx, other, nil, uuid.New(), nil, digest))
	s.Equal(int64(1), s.countInstances(other))

	// After the TTL the cap is checked again and the instance is recorded.
	s.now = s.now.Add(31 * time.Second)
	s.NoError(svc.TouchFromHeartbeat(s.ctx, agentID, nil, uuid.New(), nil, digest))
	s.Equal(int64(2), s.countInstances(agentID))

	// Reports ignore the cache: they find the cap reached (409)...
	report := applyReport(agentconfig.ModeApplySafe, baseConfig)
	s.ErrorIs(svc.UpsertReport(s.ctx, agentID, nil, uuid.New(), report), agentcfg.ErrInstanceLimit)
	// ...and are recorded as soon as a slot is free, which also clears the cache.
	s.deleteOneInstance(agentID)
	s.Equal(int64(1), s.countInstances(agentID))
	s.Require().NoError(svc.UpsertReport(s.ctx, agentID, nil, uuid.New(), report))
	s.Equal(int64(2), s.countInstances(agentID))
	s.deleteOneInstance(agentID)
	s.NoError(svc.TouchFromHeartbeat(s.ctx, agentID, nil, uuid.New(), nil, digest))
	s.Equal(int64(2), s.countInstances(agentID), "a successful insert clears the cached cap")
}

func (s *AgentCfgServiceIntegrationSuite) TestTouchFromHeartbeat() {
	agentID := s.newAgent("heartbeat")
	credID := uuid.New()

	// Without a digest nothing is ever inserted.
	s.Require().NoError(s.svc.TouchFromHeartbeat(s.ctx, agentID, &credID, uuid.New(), ptr(int64(3)), nil))
	s.Equal(int64(0), s.countInstances(agentID))

	// Without a digest an existing row only gets last_seen_at.
	reported := uuid.New()
	t0 := s.now
	s.Require().NoError(s.svc.UpsertReport(s.ctx, agentID, nil, reported, applyReport(agentconfig.ModeApplySafe, baseConfig)))
	t1 := t0.Add(3 * time.Minute)
	s.now = t1
	s.Require().NoError(s.svc.TouchFromHeartbeat(s.ctx, agentID, &credID, reported, ptr(int64(3)), nil))
	got, err := s.svc.GetInstance(s.ctx, agentID, reported)
	s.Require().NoError(err)
	s.True(got.LastSeenAt.Equal(t1))
	s.True(got.ReportedAt.Equal(t0))
	s.Nil(got.CredentialID)
	s.Nil(got.HeartbeatConfigRevision)
	s.Nil(got.HeartbeatConfigDigest)
	s.Equal(agentconfig.StatusApplied, got.ReportedStatus)

	// With a digest a new row is inserted with an empty reported status.
	hbOnly := uuid.New()
	s.Require().NoError(s.svc.TouchFromHeartbeat(s.ctx, agentID, &credID, hbOnly, ptr(int64(3)), ptr("sha256:hb")))
	got, err = s.svc.GetInstance(s.ctx, agentID, hbOnly)
	s.Require().NoError(err)
	s.Equal("", got.ReportedStatus)
	s.Equal("", got.Mode)
	s.Nil(got.Daemon)
	s.Nil(got.ReportedAt)
	s.Nil(got.BaseConfig)
	s.Equal(credID, *got.CredentialID)
	s.Equal(int64(3), *got.HeartbeatConfigRevision)
	s.Equal("sha256:hb", *got.HeartbeatConfigDigest)
	s.True(got.FirstSeenAt.Equal(t1))
	s.True(got.LastSeenAt.Equal(t1))

	// With a digest an existing reported row keeps its report columns.
	t2 := t1.Add(time.Minute)
	s.now = t2
	s.Require().NoError(s.svc.TouchFromHeartbeat(s.ctx, agentID, &credID, reported, ptr(int64(4)), ptr("sha256:hb2")))
	got, err = s.svc.GetInstance(s.ctx, agentID, reported)
	s.Require().NoError(err)
	s.True(got.LastSeenAt.Equal(t2))
	s.Equal(int64(4), *got.HeartbeatConfigRevision)
	s.Equal("sha256:hb2", *got.HeartbeatConfigDigest)
	s.Equal(credID, *got.CredentialID)
	s.Equal(agentconfig.StatusApplied, got.ReportedStatus)
	s.Equal(agentconfig.ModeApplySafe, got.Mode)
	s.JSONEq(baseConfig, string(got.BaseConfig))
	s.True(got.ReportedAt.Equal(t0))
	s.Equal(int64(2), s.countInstances(agentID))

	// Over the cap a heartbeat with a digest is silently skipped.
	capped := s.newService(agentcfg.Settings{MaxInstancesPerAgent: 2})
	s.NoError(capped.TouchFromHeartbeat(s.ctx, agentID, &credID, uuid.New(), ptr(int64(4)), ptr("sha256:hb3")))
	s.Equal(int64(2), s.countInstances(agentID))
	s.NoError(capped.TouchFromHeartbeat(s.ctx, agentID, &credID, hbOnly, ptr(int64(5)), ptr("sha256:hb4")),
		"existing instances still record heartbeats over the cap")
	got, err = s.svc.GetInstance(s.ctx, agentID, hbOnly)
	s.Require().NoError(err)
	s.Equal(int64(5), *got.HeartbeatConfigRevision)
}

func (s *AgentCfgServiceIntegrationSuite) TestListAndGetInstances() {
	agentID := s.newAgent("list-instances")
	other := s.newAgent("list-instances-other")
	older, newer := uuid.New(), uuid.New()
	report := applyReport(agentconfig.ModeApplySafe, baseConfig)
	report.Warnings = []agentconfig.FieldError{{Path: "/x", Code: "unknown-field", Message: "m"}}
	report.RemoteConfig = &agentconfig.RemoteConfig{Mode: agentconfig.ModeApplySafe}
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-time.Hour), agentID, older, report))
	s.Require().NoError(s.reportAt(s.svc, s.now, agentID, newer, report))
	s.Require().NoError(s.svc.UpsertReport(s.ctx, other, nil, uuid.New(), report))

	list, total, err := s.svc.ListInstances(s.ctx, agentID, service.PaginationParams{Page: 1, Limit: agentcfg.InstancesPageLimit})
	s.Require().NoError(err)
	s.Equal(int64(2), total)
	s.Require().Len(list, 2)
	s.Equal(newer, list[0].InstanceID, "most recently seen first")
	s.Equal(older, list[1].InstanceID)
	for _, i := range list {
		s.NotNil(i.ID)
		s.Equal(agentID, i.AgentID)
		s.Nil(i.BaseConfig, "heavy column not loaded")
		s.Nil(i.EffectiveConfig, "heavy column not loaded")
		s.NotNil(i.Warnings)
		s.NotNil(i.RemoteConfig)
		s.Equal("sha256:abc", *i.EffectiveDigest)
		s.Equal(agentconfig.StatusApplied, i.ReportedStatus)
	}

	full, err := s.svc.GetInstance(s.ctx, agentID, newer)
	s.Require().NoError(err)
	s.NotNil(full.BaseConfig)
	s.NotNil(full.EffectiveConfig)

	_, err = s.svc.GetInstance(s.ctx, other, newer)
	s.ErrorIs(err, agentcfg.ErrNotFound, "another agent's instance")
	_, err = s.svc.GetInstance(s.ctx, agentID, uuid.New())
	s.ErrorIs(err, agentcfg.ErrNotFound)

	empty, total, err := s.svc.ListInstances(s.ctx, s.newAgent("no-instances"), service.PaginationParams{Page: 1, Limit: agentcfg.InstancesPageLimit})
	s.Require().NoError(err)
	s.Zero(total)
	s.NotNil(empty)
	s.Empty(empty)
}

// ListInstances returns one page (at most InstancesPageLimit rows, newest first, ties by
// instance id) and the total; CountInstances counts every instance, not just the page's.
func (s *AgentCfgServiceIntegrationSuite) TestListInstancesPagesAndCountsAll() {
	agentID := s.newAgent("paged-instances")
	other := s.newAgent("paged-instances-other")
	s.createRevision(agentID, 0, `{"verbosity":1}`) // desired revision 1
	s.insertInstance(other, nil, s.now)

	const n = 30
	type seen struct {
		id uuid.UUID
		at time.Time
	}
	instances := make([]seen, 0, n)
	for i := 0; i < n; i++ {
		at := s.now.Add(-time.Duration(i) * time.Minute)
		if i == n-1 {
			at = instances[n-2].at // a tie on last_seen_at: instance_id decides
		}
		instances = append(instances, seen{s.insertInstance(agentID, ptr(true), at), at})
	}
	want := make([]uuid.UUID, 0, n)
	slices.SortFunc(instances, func(a, b seen) int {
		if c := b.at.Compare(a.at); c != 0 {
			return c
		}
		return strings.Compare(a.id.String(), b.id.String())
	})
	for _, i := range instances {
		want = append(want, i.id)
	}

	// States of instances beyond the first page; the rest never reported (unknown).
	set := func(id uuid.UUID, cols map[string]any) {
		s.Require().NoError(s.DB.Model(&relational.AgentInstance{}).Where("instance_id = ?", id).Updates(cols).Error)
	}
	set(want[25], map[string]any{"reported_status": agentconfig.StatusApplied, "applied_revision": 1})
	set(want[26], map[string]any{"reported_status": agentconfig.StatusRejected, "attempted_revision": 1})
	set(want[27], map[string]any{"reported_status": agentconfig.StatusFailed, "attempted_revision": 1})
	set(want[28], map[string]any{"reported_status": agentconfig.StatusApplied}) // behind, not attempted: pending
	set(want[29], map[string]any{"mode": agentconfig.ModeReport, "reported_status": agentconfig.StatusNotApplicable})

	ids := func(rows []relational.AgentInstance) []uuid.UUID {
		out := make([]uuid.UUID, 0, len(rows))
		for _, r := range rows {
			s.Nil(r.BaseConfig, "heavy column not loaded")
			s.Nil(r.EffectiveConfig, "heavy column not loaded")
			out = append(out, r.InstanceID)
		}
		return out
	}

	page, total, err := s.svc.ListInstances(s.ctx, agentID, service.PaginationParams{Page: 1, Limit: 25})
	s.Require().NoError(err)
	s.Equal(int64(n), total)
	s.Equal(want[:25], ids(page))

	page, total, err = s.svc.ListInstances(s.ctx, agentID, service.PaginationParams{Page: 2, Limit: 25, Offset: 25})
	s.Require().NoError(err)
	s.Equal(int64(n), total)
	s.Equal(want[25:], ids(page))

	page, _, err = s.svc.ListInstances(s.ctx, agentID, service.PaginationParams{Page: 2, Limit: 10, Offset: 10})
	s.Require().NoError(err)
	s.Equal(want[10:20], ids(page))

	for _, limit := range []int{0, -1, 26, 1000} {
		page, _, err = s.svc.ListInstances(s.ctx, agentID, service.PaginationParams{Page: 1, Limit: limit})
		s.Require().NoError(err)
		s.Len(page, agentcfg.InstancesPageLimit, "limit %d is capped at InstancesPageLimit", limit)
	}
	for _, offset := range []int{n, 1 << 40, -25} {
		page, total, err = s.svc.ListInstances(s.ctx, agentID, service.PaginationParams{Page: 2, Limit: 25, Offset: offset})
		s.Require().NoError(err, "offset %d", offset)
		s.Equal(int64(n), total)
		s.NotNil(page)
		s.Empty(page, "offset %d", offset)
	}

	counts, err := s.svc.CountInstances(s.ctx, agentID, 1, s.now)
	s.Require().NoError(err)
	s.Equal(agentcfg.InstanceCounts{
		Total: n, Fresh: 11, Stale: n - 11, // stale after 10 minutes by default
		InSync: 1, OutOfSync: 3,
		Pending: 1, Rejected: 1, Failed: 1, Unknown: n - 5,
	}, counts)

	counts, err = s.svc.CountInstances(s.ctx, s.newAgent("paged-instances-empty"), 0, s.now)
	s.Require().NoError(err)
	s.Equal(agentcfg.InstanceCounts{}, counts)
}

// validationFixture seeds an agent with fresh apply-mode instances plus instances that must
// never be validated against.
type validationFixture struct {
	agentID                                uuid.UUID
	freshSafe, freshAll, reportMode, stale uuid.UUID
	noBase                                 uuid.UUID
}

func (s *AgentCfgServiceIntegrationSuite) seedValidationFixture() validationFixture {
	f := validationFixture{
		agentID: s.newAgent("validation"), freshSafe: uuid.New(), freshAll: uuid.New(),
		reportMode: uuid.New(), stale: uuid.New(), noBase: uuid.New(),
	}
	safe := applyReport(agentconfig.ModeApplySafe, baseConfig)
	safe.RemoteConfig = &agentconfig.RemoteConfig{Mode: agentconfig.ModeApplySafe, TrustedSources: []string{"ghcr.io/x/*"}}
	s.Require().NoError(s.reportAt(s.svc, s.now, f.agentID, f.freshSafe, safe))

	// No reported remote-config: falls back to the base block.
	withRemote := `{"daemon":true,"verbosity":0,"remote_config":{"mode":"apply_all","poll_interval":"30s"},"plugins":{}}`
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-5*time.Minute), f.agentID, f.freshAll, applyReport(agentconfig.ModeApplyAll, withRemote)))

	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-time.Minute), f.agentID, f.reportMode, applyReport(agentconfig.ModeReport, baseConfig)))
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-time.Minute), f.agentID, f.noBase, applyReport(agentconfig.ModeApplySafe, "")))
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-time.Hour), f.agentID, f.stale, applyReport(agentconfig.ModeApplySafe, baseConfig)))
	return f
}

func byInstance(bases []agentcfg.InstanceBase) map[uuid.UUID]agentcfg.InstanceBase {
	out := map[uuid.UUID]agentcfg.InstanceBase{}
	for _, b := range bases {
		out[b.Instance.InstanceID] = b
	}
	return out
}

func (s *AgentCfgServiceIntegrationSuite) TestValidationBasesFreshInstances() {
	f := s.seedValidationFixture()

	bases, standalone, err := s.svc.ValidationBases(s.ctx, f.agentID)
	s.Require().NoError(err)
	s.False(standalone)
	s.Require().Len(bases, 2)
	s.Equal(f.freshSafe, bases[0].Instance.InstanceID, "most recently seen first")
	s.Equal(f.freshAll, bases[1].Instance.InstanceID)

	m := byInstance(bases)
	for _, b := range bases {
		s.False(b.Stale)
		s.True(b.Validated)
		s.True(b.Base.Daemon, "base decoded")
	}
	s.Require().NotNil(m[f.freshSafe].Base.API)
	s.Equal("http://api:8080", m[f.freshSafe].Base.API.URL)

	// Reported remote-config wins.
	safeRemote := m[f.freshSafe].Remote
	s.Equal(agentconfig.ModeApplySafe, safeRemote.Mode)
	s.Equal([]string{"ghcr.io/x/*"}, safeRemote.TrustedSources)
	s.Equal("60s", safeRemote.PollInterval)

	// Falls back to the base's remote_config block, normalized with hasAuth=true.
	allRemote := m[f.freshAll].Remote
	s.Equal(agentconfig.ModeApplyAll, allRemote.Mode)
	s.Equal("30s", allRemote.PollInterval)
	s.Equal([]string{}, allRemote.TrustedSources)
	s.Equal([]string{}, allRemote.OverridableConfigFlags)
	s.False(allRemote.AllowLocalSources)
}

func (s *AgentCfgServiceIntegrationSuite) TestValidationBasesFallbackAndStandalone() {
	agentID := s.newAgent("fallback")
	seenRecently, reportedRecently := uuid.New(), uuid.New()
	// Reported 200h ago but heartbeated 30m ago (stale, but seen more recently).
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-200*time.Hour), agentID, seenRecently, applyReport(agentconfig.ModeApplySafe, baseConfig)))
	saved := s.now
	s.now = saved.Add(-30 * time.Minute)
	s.Require().NoError(s.svc.TouchFromHeartbeat(s.ctx, agentID, nil, seenRecently, nil, nil))
	s.now = saved
	// Most recently reported apply-mode instance, 100h ago.
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-100*time.Hour), agentID, reportedRecently, applyReport(agentconfig.ModeApplyAll, baseConfig)))
	// Newer, but report mode (and a fresh report-mode one) or without a base.
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-2*time.Hour), agentID, uuid.New(), applyReport(agentconfig.ModeReport, baseConfig)))
	s.Require().NoError(s.reportAt(s.svc, s.now, agentID, uuid.New(), applyReport(agentconfig.ModeReport, baseConfig)))
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-time.Hour), agentID, uuid.New(), applyReport(agentconfig.ModeApplySafe, "")))

	bases, standalone, err := s.svc.ValidationBases(s.ctx, agentID)
	s.Require().NoError(err)
	s.False(standalone)
	s.Require().Len(bases, 1)
	s.Equal(reportedRecently, bases[0].Instance.InstanceID)
	s.True(bases[0].Stale)
	s.True(bases[0].Validated)
	s.Equal(agentconfig.ModeApplyAll, bases[0].Remote.Mode, "no remote block anywhere: the instance mode")

	// Only report-mode / base-less instances: standalone.
	onlyIneligible := s.newAgent("standalone")
	s.Require().NoError(s.reportAt(s.svc, s.now, onlyIneligible, uuid.New(), applyReport(agentconfig.ModeReport, baseConfig)))
	s.Require().NoError(s.reportAt(s.svc, s.now, onlyIneligible, uuid.New(), applyReport(agentconfig.ModeApplyAll, "")))
	s.Require().NoError(s.svc.TouchFromHeartbeat(s.ctx, onlyIneligible, nil, uuid.New(), ptr(int64(1)), ptr("d")))
	bases, standalone, err = s.svc.ValidationBases(s.ctx, onlyIneligible)
	s.Require().NoError(err)
	s.True(standalone)
	s.Empty(bases)

	bases, standalone, err = s.svc.ValidationBases(s.ctx, s.newAgent("no-instances"))
	s.Require().NoError(err)
	s.True(standalone)
	s.Empty(bases)
}

// Instances that report the same base (whatever its key order or whitespace) share one
// BaseKey and one decoded base; each keeps its own instance fields and remote-config.
func (s *AgentCfgServiceIntegrationSuite) TestValidationBasesGroupsByBaseContent() {
	agentID := s.newAgent("grouped-bases")
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	reordered := `{ "verbosity":0, "plugins":{"p1":{"policies":["ghcr.io/x/pol:v1"],"source":"ghcr.io/x/p1:v1"}}, "api":{"auth":{"client_id":"cid"},"url":"http://api:8080"}, "daemon":true }`
	other := `{"daemon":true,"verbosity":1,"plugins":{}}`
	for _, in := range []struct {
		id       uuid.UUID
		base     string
		host     string
		at       time.Duration
		trusted  []string
		instMode string
	}{
		{a, baseConfig, "host-a", 0, []string{"ghcr.io/a/*"}, agentconfig.ModeApplySafe},
		{b, reordered, "host-b", -time.Minute, []string{"ghcr.io/b/*"}, agentconfig.ModeApplyAll},
		{c, other, "host-c", -2 * time.Minute, nil, agentconfig.ModeApplySafe},
	} {
		r := applyReport(in.instMode, in.base)
		r.Hostname = in.host
		r.RemoteConfig = &agentconfig.RemoteConfig{Mode: in.instMode, TrustedSources: in.trusted}
		s.Require().NoError(s.reportAt(s.svc, s.now.Add(in.at), agentID, in.id, r))
	}

	bases, standalone, err := s.svc.ValidationBases(s.ctx, agentID)
	s.Require().NoError(err)
	s.False(standalone)
	s.Require().Len(bases, 3, "every instance of the validation set is still listed")
	s.Equal([]uuid.UUID{a, b, c}, []uuid.UUID{bases[0].Instance.InstanceID, bases[1].Instance.InstanceID, bases[2].Instance.InstanceID})

	m := byInstance(bases)
	s.NotEmpty(m[a].BaseKey)
	s.Equal(m[a].BaseKey, m[b].BaseKey, "same base content, same key")
	s.NotEqual(m[a].BaseKey, m[c].BaseKey)
	s.Equal(m[a].Base, m[b].Base)
	s.Equal(int32(1), m[c].Base.Verbosity)
	s.Nil(m[a].Instance.BaseConfig, "the base is loaded once per group, not per instance")

	s.Equal("host-a", *m[a].Instance.Hostname)
	s.Equal("host-b", *m[b].Instance.Hostname)
	s.Equal([]string{"ghcr.io/a/*"}, m[a].Remote.TrustedSources)
	s.Equal([]string{"ghcr.io/b/*"}, m[b].Remote.TrustedSources)
	s.Equal(agentconfig.ModeApplyAll, m[b].Remote.Mode)
	for _, base := range bases {
		s.True(base.Validated)
		s.False(base.Stale)
	}
}

func (s *AgentCfgServiceIntegrationSuite) TestPreviewBases() {
	f := s.seedValidationFixture()

	set, err := s.svc.PreviewBases(s.ctx, f.agentID)
	s.Require().NoError(err)
	s.Zero(set.Omitted)
	s.Len(set.Validation, 2)
	m := byInstance(set.Instances)
	s.Require().Len(m, 4, "every instance with a base; base-less excluded")
	s.NotContains(m, f.noBase)

	s.True(m[f.freshSafe].Validated)
	s.True(m[f.freshAll].Validated)
	s.False(m[f.reportMode].Validated)
	s.False(m[f.stale].Validated)
	s.False(m[f.freshSafe].Stale)
	s.False(m[f.reportMode].Stale)
	s.True(m[f.stale].Stale)
	s.Equal(agentconfig.ModeReport, m[f.reportMode].Remote.Mode)

	// Fallback: only the most recently reported stale instance is validated.
	agentID := s.newAgent("preview-fallback")
	older, newer := uuid.New(), uuid.New()
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-3*time.Hour), agentID, older, applyReport(agentconfig.ModeApplySafe, baseConfig)))
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-2*time.Hour), agentID, newer, applyReport(agentconfig.ModeApplySafe, baseConfig)))
	set, err = s.svc.PreviewBases(s.ctx, agentID)
	s.Require().NoError(err)
	bases := set.Instances
	s.Require().Len(bases, 2)
	s.Equal(newer, bases[0].Instance.InstanceID)
	s.True(bases[0].Stale)
	s.True(bases[0].Validated)
	s.True(bases[1].Stale)
	s.False(bases[1].Validated)
}

func (s *AgentCfgServiceIntegrationSuite) TestPreviewBasesBounded() {
	agentID := s.newAgent("preview-bounded")
	// The validated instance is older than every report-mode one, which are not validated
	// and outnumber the preview bound.
	validated := uuid.New()
	s.Require().NoError(s.reportAt(s.svc, s.now.Add(-5*time.Minute), agentID, validated, applyReport(agentconfig.ModeApplySafe, baseConfig)))
	var others []uuid.UUID
	for i := range agentcfg.PreviewMaxInstances + 5 {
		id := uuid.New()
		others = append(others, id)
		s.Require().NoError(s.reportAt(s.svc, s.now.Add(-time.Duration(i+1)*time.Second), agentID, id, applyReport(agentconfig.ModeReport, baseConfig)))
	}

	set, err := s.svc.PreviewBases(s.ctx, agentID)
	s.Require().NoError(err)
	s.Len(set.Validation, 1)
	s.Require().Len(set.Instances, agentcfg.PreviewMaxInstances)
	s.EqualValues(6, set.Omitted)
	s.Equal(validated, set.Instances[0].Instance.InstanceID, "validated instances first")
	s.True(set.Instances[0].Validated)
	s.Equal(others[0], set.Instances[1].Instance.InstanceID, "then newest first")
	s.False(set.Instances[1].Validated)
}

func (s *AgentCfgServiceIntegrationSuite) TestDeleteInstancesForAgentKeepsRevisions() {
	agentA := s.newAgent("delete-a")
	agentB := s.newAgent("delete-b")
	s.createRevision(agentA, 0, `{"verbosity":1}`)
	s.createRevision(agentA, 1, `{"verbosity":2}`)
	report := applyReport(agentconfig.ModeApplySafe, baseConfig)
	s.Require().NoError(s.svc.UpsertReport(s.ctx, agentA, nil, uuid.New(), report))
	s.Require().NoError(s.svc.UpsertReport(s.ctx, agentA, nil, uuid.New(), report))
	keep := uuid.New()
	s.Require().NoError(s.svc.UpsertReport(s.ctx, agentB, nil, keep, report))

	s.Require().NoError(agentcfg.DeleteInstancesForAgent(s.DB, agentA))

	s.Equal(int64(0), s.countInstances(agentA))
	s.Equal(int64(1), s.countInstances(agentB))
	_, err := s.svc.GetInstance(s.ctx, agentB, keep)
	s.NoError(err)
	n, err := s.svc.CurrentRevisionNumber(s.ctx, agentA)
	s.Require().NoError(err)
	s.Equal(int64(2), n, "revisions are kept")
}

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

func (s *AgentCfgServiceIntegrationSuite) TestPruneInstances() {
	agentID := s.newAgent("prune")
	now := s.now
	oneShotOld := s.insertInstance(agentID, ptr(false), now.Add(-25*time.Hour))
	oneShotRecent := s.insertInstance(agentID, ptr(false), now.Add(-23*time.Hour))
	daemon25h := s.insertInstance(agentID, ptr(true), now.Add(-25*time.Hour))
	daemonOld := s.insertInstance(agentID, ptr(true), now.Add(-721*time.Hour))
	null25h := s.insertInstance(agentID, nil, now.Add(-25*time.Hour))
	nullOld := s.insertInstance(agentID, nil, now.Add(-721*time.Hour))

	deleted, err := agentcfg.PruneInstances(s.ctx, s.DB, agentcfg.Settings{}, now)
	s.Require().NoError(err)
	s.Equal(int64(3), deleted)

	remaining := map[uuid.UUID]bool{}
	list, _, err := s.svc.ListInstances(s.ctx, agentID, service.PaginationParams{Page: 1, Limit: agentcfg.InstancesPageLimit})
	s.Require().NoError(err)
	for _, i := range list {
		remaining[i.InstanceID] = true
	}
	s.False(remaining[oneShotOld], "daemon=false pruned after 24h")
	s.True(remaining[oneShotRecent])
	s.True(remaining[daemon25h], "daemon=true kept at 25h")
	s.False(remaining[daemonOld], "daemon=true pruned after 720h")
	s.True(remaining[null25h], "daemon NULL treated like a daemon")
	s.False(remaining[nullOld])

	deleted, err = agentcfg.PruneInstances(s.ctx, s.DB, agentcfg.Settings{}, now)
	s.Require().NoError(err)
	s.Equal(int64(0), deleted, "idempotent")
}
