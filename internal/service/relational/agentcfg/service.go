// Package agentcfg stores and serves agent remote-configuration revisions (append-only
// overlays per agent) and the agent instances that report against them.
package agentcfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// capReachedTTL is how long the service remembers that an agent is at its instance cap with
// every counted instance fresh (nothing to replace), so heartbeats from unregistered
// instances skip the locked count meanwhile.
const capReachedTTL = time.Minute

// Settings tunes instance freshness, retention and the per-agent instance cap.
type Settings struct {
	InstanceStaleAfter       time.Duration // fresh <=> last_seen_at >= now - InstanceStaleAfter
	InstanceRetention        time.Duration // daemon (or unknown) instances
	OneShotInstanceRetention time.Duration // daemon=false instances (R37)
	MaxInstancesPerAgent     int           // non-prunable instances per agent; the oldest stale one is replaced when full
}

// WithDefaults fills zero or negative values with config.DefaultAgentsConfig (R37, R14), the
// single source of the defaults.
func (s Settings) WithDefaults() Settings {
	d := config.DefaultAgentsConfig()
	if s.InstanceStaleAfter <= 0 {
		s.InstanceStaleAfter = d.InstanceStaleAfter
	}
	if s.InstanceRetention <= 0 {
		s.InstanceRetention = d.InstanceRetention
	}
	if s.OneShotInstanceRetention <= 0 {
		s.OneShotInstanceRetention = d.OneShotInstanceRetention
	}
	if s.MaxInstancesPerAgent <= 0 {
		s.MaxInstancesPerAgent = d.MaxInstancesPerAgent
	}
	return s
}

// SettingsFromConfig maps the CCF_AGENT_* config onto Settings (nil config or nil Agents =>
// defaults).
func SettingsFromConfig(c *config.Config) Settings {
	if c == nil || c.Agents == nil {
		return Settings{}.WithDefaults()
	}
	cfg := c.Agents
	return Settings{
		InstanceStaleAfter:       cfg.InstanceStaleAfter,
		InstanceRetention:        cfg.InstanceRetention,
		OneShotInstanceRetention: cfg.OneShotInstanceRetention,
		MaxInstancesPerAgent:     cfg.MaxInstancesPerAgent,
	}.WithDefaults()
}

var (
	// ErrNotFound is returned when the agent, revision or instance does not exist.
	ErrNotFound = errors.New("not found")
	// ErrRevisionConflict is returned (wrapped in *RevisionConflictError) when the expected
	// revision is not the current one.
	ErrRevisionConflict = errors.New("configuration revision conflict")
	// ErrInstanceLimit is returned when a new instance would exceed the per-agent cap.
	ErrInstanceLimit = errors.New("instance limit reached")
)

// RevisionConflictError carries the current revision of a failed CreateRevision.
type RevisionConflictError struct {
	Current int64
}

func (e *RevisionConflictError) Error() string {
	return fmt.Sprintf("%s: current revision is %d", ErrRevisionConflict.Error(), e.Current)
}

// Is makes errors.Is(err, ErrRevisionConflict) true.
func (e *RevisionConflictError) Is(target error) bool { return target == ErrRevisionConflict }

// Service is the agent remote-configuration store.
type Service struct {
	db       *gorm.DB
	settings Settings
	logger   *zap.SugaredLogger
	now      func() time.Time

	capMu      sync.Mutex
	capReached map[uuid.UUID]time.Time // agent -> when its instance cap was last found reached
}

// NewService builds a Service. Zero settings take the defaults; a nil logger is a no-op.
func NewService(db *gorm.DB, s Settings, logger *zap.SugaredLogger) *Service {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Service{
		db:         db,
		settings:   s.WithDefaults(),
		logger:     logger,
		now:        func() time.Time { return time.Now().UTC() },
		capReached: map[uuid.UUID]time.Time{},
	}
}

// Settings returns the effective settings.
func (s *Service) Settings() Settings { return s.settings }

// Now returns the service clock (UTC).
func (s *Service) Now() time.Time { return s.now() }

// SetClock overrides the service clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// ---- Revisions ----

// Current returns the latest revision of an agent, or nil (revision 0) when none exists.
func (s *Service) Current(ctx context.Context, agentID uuid.UUID) (*relational.AgentConfigRevision, error) {
	var rev relational.AgentConfigRevision
	err := s.db.WithContext(ctx).
		Where("agent_id = ?", agentID).
		Order("revision DESC").
		Limit(1).
		Take(&rev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rev, nil
}

// CurrentRevisionNumber returns the latest revision number, 0 when none exists.
func (s *Service) CurrentRevisionNumber(ctx context.Context, agentID uuid.UUID) (int64, error) {
	var cur int64
	err := s.db.WithContext(ctx).Model(&relational.AgentConfigRevision{}).
		Where("agent_id = ?", agentID).
		Select("COALESCE(MAX(revision), 0)").
		Scan(&cur).Error
	return cur, err
}

// GetRevision returns one revision or ErrNotFound.
func (s *Service) GetRevision(ctx context.Context, agentID uuid.UUID, rev int64) (*relational.AgentConfigRevision, error) {
	var out relational.AgentConfigRevision
	err := s.db.WithContext(ctx).Where("agent_id = ? AND revision = ?", agentID, rev).Take(&out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RevisionMeta is a revision without its overlay (list views, R12).
type RevisionMeta struct {
	ID          uuid.UUID
	AgentID     uuid.UUID
	Revision    int64
	CreatedAt   time.Time
	Comment     *string
	CreatedBy   string
	CreatedByID *uuid.UUID
	RevertOf    *int64
	OverlaySize int // bytes of the stored overlay's text form
}

// ListRevisions returns one page of revisions, newest first, and the total count.
func (s *Service) ListRevisions(ctx context.Context, agentID uuid.UUID, p service.PaginationParams) ([]RevisionMeta, int64, error) {
	db := s.db.WithContext(ctx)
	var total int64
	if err := db.Model(&relational.AgentConfigRevision{}).Where("agent_id = ?", agentID).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []RevisionMeta
	err := db.Model(&relational.AgentConfigRevision{}).
		Select("id, agent_id, revision, created_at, comment, created_by, created_by_id, revert_of, octet_length(overlay::text) AS overlay_size").
		Where("agent_id = ?", agentID).
		Order("revision DESC").
		Limit(p.Limit).
		Offset(p.Offset).
		Scan(&rows).Error
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// CreateRevisionParams are the inputs of CreateRevision.
type CreateRevisionParams struct {
	AgentID          uuid.UUID
	ExpectedRevision int64
	Overlay          json.RawMessage
	Comment          *string
	CreatedBy        string
	CreatedByID      *uuid.UUID
	RevertOf         *int64
}

// CreateRevision appends revision ExpectedRevision+1 in one transaction: it locks the agent
// row, re-reads the current revision and fails with *RevisionConflictError when it is not
// ExpectedRevision. The agent row lock serializes writers, so the insert cannot hit the
// unique (agent_id, revision) index; any insert error is returned as is. The returned row
// is read back after the insert, so its Overlay bytes are the stored form GetRevision and
// ListRevisions (overlay size) see.
func (s *Service) CreateRevision(ctx context.Context, p CreateRevisionParams) (*relational.AgentConfigRevision, error) {
	var created *relational.AgentConfigRevision
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var agent relational.Agent
		if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Select("id").
			Where("id = ?", p.AgentID).
			Take(&agent).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		var cur int64
		if err := tx.Model(&relational.AgentConfigRevision{}).
			Where("agent_id = ?", p.AgentID).
			Select("COALESCE(MAX(revision), 0)").
			Scan(&cur).Error; err != nil {
			return err
		}
		if cur != p.ExpectedRevision {
			return &RevisionConflictError{Current: cur}
		}
		rev := &relational.AgentConfigRevision{
			AgentID:     p.AgentID,
			Revision:    cur + 1,
			Overlay:     datatypes.JSON(p.Overlay),
			Comment:     p.Comment,
			CreatedBy:   p.CreatedBy,
			CreatedByID: p.CreatedByID,
			RevertOf:    p.RevertOf,
			CreatedAt:   s.now(),
		}
		if err := tx.Create(rev).Error; err != nil {
			return err
		}
		var stored relational.AgentConfigRevision
		if err := tx.Where("agent_id = ? AND revision = ?", p.AgentID, rev.Revision).Take(&stored).Error; err != nil {
			return err
		}
		created = &stored
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// ---- Instances ----

// reportColumns are the columns a config report overwrites.
var reportColumns = []string{
	"credential_id", "hostname", "agent_version", "mode", "daemon",
	"last_seen_at", "reported_at", "applied_revision", "attempted_revision",
	"reported_status", "apply_reason", "apply_error", "truncated", "warnings",
	"base_config", "effective_config", "effective_digest", "remote_config",
	"unsafe_changes", "plugins", "updated_at",
}

// UpsertReport stores a (validated, re-redacted) config report. A new instance at the
// per-agent cap replaces the oldest stale instance, or fails with ErrInstanceLimit when every
// counted instance is fresh; prune-eligible rows do not count (R37).
func (s *Service) UpsertReport(ctx context.Context, agentID uuid.UUID, credentialID *uuid.UUID, instanceID uuid.UUID, r agentconfig.Report) error {
	now := s.now()
	row, err := reportRow(agentID, credentialID, instanceID, r, now)
	if err != nil {
		return err
	}
	return s.upsert(ctx, row, reportColumns, false)
}

func reportRow(agentID uuid.UUID, credentialID *uuid.UUID, instanceID uuid.UUID, r agentconfig.Report, now time.Time) (*relational.AgentInstance, error) {
	daemon := r.Daemon
	row := &relational.AgentInstance{
		AgentID:           agentID,
		InstanceID:        instanceID,
		CredentialID:      credentialID,
		Hostname:          optionalString(r.Hostname),
		AgentVersion:      optionalString(r.AgentVersion),
		Mode:              r.Mode,
		Daemon:            &daemon,
		FirstSeenAt:       now,
		LastSeenAt:        now,
		ReportedAt:        &now,
		AppliedRevision:   r.AppliedRevision,
		AttemptedRevision: r.AttemptedRevision,
		ReportedStatus:    r.Status,
		ApplyReason:       optionalString(r.Reason),
		ApplyError:        r.Error,
		Truncated:         r.Truncated,
		BaseConfig:        rawOrNil(r.Base),
		EffectiveConfig:   rawOrNil(r.Effective),
		EffectiveDigest:   optionalString(r.EffectiveDigest),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	var err error
	if row.Warnings, err = jsonOrNil(r.Warnings); err != nil {
		return nil, err
	}
	if r.RemoteConfig != nil {
		if row.RemoteConfig, err = jsonOrNil(r.RemoteConfig); err != nil {
			return nil, err
		}
	}
	if row.UnsafeChanges, err = jsonOrNil(r.Unsafe); err != nil {
		return nil, err
	}
	if row.Plugins, err = jsonOrNil(r.Plugins); err != nil {
		return nil, err
	}
	return row, nil
}

// TouchFromHeartbeat records an authenticated heartbeat (R11). With a digest it upserts
// only last_seen_at, credential_id and the heartbeat_* columns (a new row keeps an empty
// reported status; over the cap it is silently skipped, with a warning at most once per
// agent per capReachedTTL, and for capReachedTTL after the cap was found reached a new
// instance skips the cap check altogether). Without a digest (an old agent, or mode off) it
// only updates last_seen_at of an existing row and never inserts, so old agents' per-reload
// random instance ids never flood the table.
func (s *Service) TouchFromHeartbeat(ctx context.Context, agentID uuid.UUID, credentialID *uuid.UUID, instanceID uuid.UUID, rev *int64, digest *string) error {
	now := s.now()
	if digest == nil {
		return s.db.WithContext(ctx).Model(&relational.AgentInstance{}).
			Where("agent_id = ? AND instance_id = ?", agentID, instanceID).
			Updates(map[string]any{"last_seen_at": now, "updated_at": now}).Error
	}
	row := &relational.AgentInstance{
		AgentID:                 agentID,
		InstanceID:              instanceID,
		CredentialID:            credentialID,
		FirstSeenAt:             now,
		LastSeenAt:              now,
		HeartbeatConfigRevision: rev,
		HeartbeatConfigDigest:   digest,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	err := s.upsert(ctx, row, []string{"last_seen_at", "credential_id", "heartbeat_config_revision", "heartbeat_config_digest", "updated_at"}, true)
	if errors.Is(err, ErrInstanceLimit) {
		return nil
	}
	return err
}

// upsert updates the instance row when it exists, else inserts it after the cap check under
// a lock on the agent row (so concurrent first reports cannot overshoot the cap). The update
// writes exactly the given columns from row, zero values included; UpdateColumns (no hooks)
// keeps updated_at at row.UpdatedAt (the service clock). With skipWhenCapped, a new instance
// of an agent whose cap was found reached within capReachedTTL fails with ErrInstanceLimit
// without the locked count.
func (s *Service) upsert(ctx context.Context, row *relational.AgentInstance, columns []string, skipWhenCapped bool) error {
	db := s.db.WithContext(ctx)
	res := db.Model(&relational.AgentInstance{}).
		Where("agent_id = ? AND instance_id = ?", row.AgentID, row.InstanceID).
		Select(columns).
		UpdateColumns(row)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		return nil
	}
	if skipWhenCapped && s.capReachedRecently(row.AgentID) {
		return ErrInstanceLimit
	}
	err := s.insertUnderCap(db, row, columns)
	switch {
	case errors.Is(err, ErrInstanceLimit):
		if s.markCapReached(row.AgentID) {
			s.logger.Warnw("Agent instance cap reached; new instances are not recorded",
				"agentID", row.AgentID, "instanceID", row.InstanceID, "max", s.settings.MaxInstancesPerAgent)
		}
	case err == nil:
		s.clearCapReached(row.AgentID)
	}
	return err
}

// insertUnderCap inserts a new instance row under the per-agent cap (R37). When the agent
// already has MaxInstancesPerAgent non-prunable instances, the oldest stale one among them is
// deleted to make room (instance ids change on restart, so a restarted daemon's old ids must
// not lock out its new ones); when every one of them is fresh it fails with
// ErrInstanceLimit. So the non-prunable rows of an agent never exceed the cap.
func (s *Service) insertUnderCap(db *gorm.DB, row *relational.AgentInstance, columns []string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var agent relational.Agent
		if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Select("id").Where("id = ?", row.AgentID).Take(&agent).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		now := row.LastSeenAt
		count, err := s.countActiveInstances(tx, row.AgentID, now)
		if err != nil {
			return err
		}
		if count >= int64(s.settings.MaxInstancesPerAgent) {
			evicted, err := s.evictOldestStaleInstance(tx, row.AgentID, now)
			if err != nil {
				return err
			}
			if !evicted {
				return ErrInstanceLimit
			}
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "agent_id"}, {Name: "instance_id"}},
			DoUpdates: clause.AssignmentColumns(columns),
		}).Create(row).Error
	})
}

// notPrunableClause selects the instances that are not eligible for pruning (R37); its two
// arguments are the one-shot and the daemon retention cutoffs. "daemon IS FALSE" (not
// "daemon = false") keeps unknown-daemon rows counted like daemon rows, as PruneInstances
// keeps them: with "= false" a NULL daemon makes the NOT(...) NULL and the row silently
// drops out.
const notPrunableClause = "NOT ((daemon IS FALSE AND last_seen_at < ?) OR last_seen_at < ?)"

// countActiveInstances counts the instances that are not eligible for pruning (R37).
func (s *Service) countActiveInstances(tx *gorm.DB, agentID uuid.UUID, now time.Time) (int64, error) {
	var count int64
	err := tx.Model(&relational.AgentInstance{}).
		Where("agent_id = ?", agentID).
		Where(notPrunableClause, now.Add(-s.settings.OneShotInstanceRetention), now.Add(-s.settings.InstanceRetention)).
		Count(&count).Error
	return count, err
}

// evictOldestStaleInstance deletes the least recently seen stale instance (IsStale:
// last_seen_at < now - InstanceStaleAfter) among the agent's non-prunable ones, the rows the
// cap counts, and reports whether there was one.
func (s *Service) evictOldestStaleInstance(tx *gorm.DB, agentID uuid.UUID, now time.Time) (bool, error) {
	var victim relational.AgentInstance
	res := tx.Select("id", "instance_id").
		Where("agent_id = ? AND last_seen_at < ?", agentID, now.Add(-s.settings.InstanceStaleAfter)).
		Where(notPrunableClause, now.Add(-s.settings.OneShotInstanceRetention), now.Add(-s.settings.InstanceRetention)).
		Order("last_seen_at ASC, instance_id").
		Limit(1).
		Find(&victim)
	if res.Error != nil || res.RowsAffected == 0 {
		return false, res.Error
	}
	if err := tx.Delete(&relational.AgentInstance{}, "id = ?", victim.ID).Error; err != nil {
		return false, err
	}
	s.logger.Debugw("Agent instance cap reached; replaced the oldest stale instance",
		"agentID", agentID, "evictedInstanceID", victim.InstanceID)
	return true, nil
}

// capReachedRecently reports whether agentID's instance cap was found reached within
// capReachedTTL.
func (s *Service) capReachedRecently(agentID uuid.UUID) bool {
	s.capMu.Lock()
	defer s.capMu.Unlock()
	at, ok := s.capReached[agentID]
	return ok && s.now().Sub(at) < capReachedTTL
}

// markCapReached records that agentID's instance cap is reached and reports whether that is
// news (not already recorded within capReachedTTL), i.e. whether to log it.
func (s *Service) markCapReached(agentID uuid.UUID) bool {
	s.capMu.Lock()
	defer s.capMu.Unlock()
	now := s.now()
	if at, ok := s.capReached[agentID]; ok && now.Sub(at) < capReachedTTL {
		return false
	}
	s.capReached[agentID] = now
	return true
}

// clearCapReached forgets that agentID's cap was reached (a new instance was inserted).
func (s *Service) clearCapReached(agentID uuid.UUID) {
	s.capMu.Lock()
	defer s.capMu.Unlock()
	delete(s.capReached, agentID)
}

// summaryColumns are the instance columns loaded for list views (no base/effective).
var summaryColumns = []string{
	"id", "created_at", "updated_at", "agent_id", "instance_id", "credential_id",
	"hostname", "agent_version", "mode", "daemon", "first_seen_at", "last_seen_at",
	"reported_at", "applied_revision", "attempted_revision", "reported_status",
	"apply_reason", "apply_error", "truncated", "warnings", "effective_digest",
	"remote_config", "unsafe_changes", "plugins",
	"heartbeat_config_revision", "heartbeat_config_digest",
}

// ListInstances returns an agent's instances (most recently seen first) without the heavy
// base/effective columns. It is deliberately unpaginated: the UI needs every row for its
// counts, the instance count is capped and pruned, and normalizeReport bounds the summary
// columns (warnings, unsafe changes, plugins).
func (s *Service) ListInstances(ctx context.Context, agentID uuid.UUID) ([]relational.AgentInstance, error) {
	var out []relational.AgentInstance
	err := s.db.WithContext(ctx).
		Select(summaryColumns).
		Where("agent_id = ?", agentID).
		Order("last_seen_at DESC, instance_id").
		Find(&out).Error
	return out, err
}

// GetInstance returns one instance of an agent (all columns) or ErrNotFound.
func (s *Service) GetInstance(ctx context.Context, agentID, instanceID uuid.UUID) (*relational.AgentInstance, error) {
	var out relational.AgentInstance
	err := s.db.WithContext(ctx).Where("agent_id = ? AND instance_id = ?", agentID, instanceID).Take(&out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRevisionsForAgent removes every configuration revision of an agent (agent deletion).
// It is the purge path for an overlay that held a secret, so it bypasses the append-only
// BeforeDelete hook, which still blocks every other delete of a revision.
func DeleteRevisionsForAgent(tx *gorm.DB, agentID uuid.UUID) error {
	return tx.Session(&gorm.Session{SkipHooks: true}).
		Where("agent_id = ?", agentID).
		Delete(&relational.AgentConfigRevision{}).Error
}

// ---- Derived state ----

// IsStale reports whether an instance was last seen before now - InstanceStaleAfter.
func IsStale(i relational.AgentInstance, now time.Time, s Settings) bool {
	s = s.WithDefaults()
	return i.LastSeenAt.Before(now.Add(-s.InstanceStaleAfter))
}

// DeriveStatus returns the displayed status of an instance (R10): unknown when it never
// reported; the reported status in report/off mode; pending when an apply-mode instance is
// behind the desired revision and has not attempted it yet; otherwise the reported status.
func DeriveStatus(i relational.AgentInstance, desired int64) string {
	switch {
	case i.ReportedStatus == "":
		return agentconfig.StatusUnknown
	case i.Mode == agentconfig.ModeReport || i.Mode == agentconfig.ModeOff:
		return i.ReportedStatus
	case desired > deref(i.AppliedRevision) &&
		(i.AttemptedRevision == nil || *i.AttemptedRevision < desired):
		return agentconfig.StatusPending
	default:
		return i.ReportedStatus
	}
}

// Sync statuses.
const (
	SyncInSync        = "in-sync"
	SyncOutOfSync     = "out-of-sync"
	SyncNotApplicable = "not-applicable"
	SyncUnknown       = "unknown"
)

// DeriveSyncStatus: report/off => not-applicable; never reported => unknown;
// COALESCE(applied,0) == desired => in-sync; else out-of-sync.
func DeriveSyncStatus(i relational.AgentInstance, desired int64) string {
	switch {
	case i.Mode == agentconfig.ModeReport || i.Mode == agentconfig.ModeOff:
		return SyncNotApplicable
	case i.ReportedStatus == "":
		return SyncUnknown
	case deref(i.AppliedRevision) == desired:
		return SyncInSync
	default:
		return SyncOutOfSync
	}
}

func deref(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func optionalString(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func rawOrNil(raw json.RawMessage) datatypes.JSON {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return datatypes.JSON(raw)
}

// jsonOrNil encodes v, storing SQL NULL for nil/empty slices.
func jsonOrNil[T any](v T) (datatypes.JSON, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if slices.Contains([]string{"null", "[]"}, string(raw)) {
		return nil, nil
	}
	return datatypes.JSON(raw), nil
}
