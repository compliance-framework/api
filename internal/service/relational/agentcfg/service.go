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
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Defaults for Settings (R37, R14).
const (
	DefaultInstanceStaleAfter       = 10 * time.Minute
	DefaultInstanceRetention        = 720 * time.Hour
	DefaultOneShotInstanceRetention = 24 * time.Hour
	DefaultMaxInstancesPerAgent     = 500
)

// Settings tunes instance freshness, retention and the per-agent instance cap.
type Settings struct {
	InstanceStaleAfter       time.Duration // fresh <=> last_seen_at >= now - InstanceStaleAfter
	InstanceRetention        time.Duration // daemon (or unknown) instances
	OneShotInstanceRetention time.Duration // daemon=false instances (R37)
	MaxInstancesPerAgent     int
}

// WithDefaults fills zero or negative values with the defaults.
func (s Settings) WithDefaults() Settings {
	if s.InstanceStaleAfter <= 0 {
		s.InstanceStaleAfter = DefaultInstanceStaleAfter
	}
	if s.InstanceRetention <= 0 {
		s.InstanceRetention = DefaultInstanceRetention
	}
	if s.OneShotInstanceRetention <= 0 {
		s.OneShotInstanceRetention = DefaultOneShotInstanceRetention
	}
	if s.MaxInstancesPerAgent <= 0 {
		s.MaxInstancesPerAgent = DefaultMaxInstancesPerAgent
	}
	return s
}

// SettingsFromConfig maps the CCF_AGENT_* config onto Settings (nil => defaults).
func SettingsFromConfig(cfg *config.AgentsConfig) Settings {
	if cfg == nil {
		return Settings{}.WithDefaults()
	}
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
}

// NewService builds a Service. Zero settings take the defaults; a nil logger is a no-op.
func NewService(db *gorm.DB, s Settings, logger *zap.SugaredLogger) *Service {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Service{db: db, settings: s.WithDefaults(), logger: logger, now: func() time.Time { return time.Now().UTC() }}
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

// BundlesFirstSeen returns, for every policy bundle defined by the CURRENT revision's
// overlay, the created_at of the oldest revision in the contiguous run of revisions (walking
// down from the current one) that define it (12.6). A bundle removed and re-added gets the
// later time. Only overlay-defined bundles appear. Postgres only.
func (s *Service) BundlesFirstSeen(ctx context.Context, agentID uuid.UUID) (map[string]time.Time, error) {
	type row struct {
		Revision  int64
		CreatedAt time.Time
		Key       *string
	}
	var rows []row
	err := s.db.WithContext(ctx).Raw(`
		SELECT r.revision, r.created_at, k.key
		FROM ccf_agent_config_revisions r
		LEFT JOIN LATERAL (
			SELECT e.key
			FROM jsonb_each(
				CASE WHEN jsonb_typeof(r.overlay->'policy_bundles') = 'object' THEN r.overlay->'policy_bundles' ELSE '{}'::jsonb END
			) AS e(key, value)
			WHERE jsonb_typeof(e.value) = 'object' -- a null value deletes a bundle; it does not define one
		) AS k ON true
		WHERE r.agent_id = ?
		ORDER BY r.revision DESC`, agentID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return map[string]time.Time{}, nil
	}

	type revision struct {
		number    int64
		createdAt time.Time
		keys      map[string]bool
	}
	var revs []revision // newest first; rows are ordered by revision DESC
	for _, r := range rows {
		if len(revs) == 0 || revs[len(revs)-1].number != r.Revision {
			revs = append(revs, revision{number: r.Revision, createdAt: r.CreatedAt, keys: map[string]bool{}})
		}
		if r.Key != nil {
			revs[len(revs)-1].keys[*r.Key] = true
		}
	}

	out := map[string]time.Time{}
	for key := range revs[0].keys {
		first := revs[0].createdAt
		for _, rv := range revs[1:] {
			if !rv.keys[key] {
				break
			}
			first = rv.createdAt
		}
		out[key] = first
	}
	return out, nil
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
// ExpectedRevision. A unique violation (a concurrent writer) also maps to a conflict.
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
			if isUniqueViolation(err) {
				return &RevisionConflictError{Current: cur + 1}
			}
			return err
		}
		created = rev
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, gorm.ErrDuplicatedKey) || (errors.As(err, &pgErr) && pgErr.Code == "23505")
}

// ---- Instances ----

// reportColumns are the columns a config report overwrites.
var reportColumns = []string{
	"credential_id", "hostname", "agent_version", "mode", "daemon",
	"last_seen_at", "reported_at", "applied_revision", "attempted_revision",
	"reported_status", "apply_reason", "apply_error", "truncated", "warnings",
	"base_config", "effective_config", "effective_digest", "remote_config",
	"policy_bundles", "policy_errors", "unsafe_changes", "updated_at",
}

// UpsertReport stores a (validated, re-redacted) config report. A new instance over the
// per-agent cap fails with ErrInstanceLimit; prune-eligible rows do not count (R37).
func (s *Service) UpsertReport(ctx context.Context, agentID uuid.UUID, credentialID *uuid.UUID, instanceID uuid.UUID, r agentconfig.Report) error {
	now := s.now()
	row, err := reportRow(agentID, credentialID, instanceID, r, now)
	if err != nil {
		return err
	}
	return s.upsert(ctx, row, reportColumns)
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
	if row.PolicyBundles, err = jsonOrNil(r.PolicyBundles); err != nil {
		return nil, err
	}
	if row.PolicyErrors, err = jsonOrNil(r.PolicyErrors); err != nil {
		return nil, err
	}
	if row.UnsafeChanges, err = jsonOrNil(r.Unsafe); err != nil {
		return nil, err
	}
	return row, nil
}

// TouchFromHeartbeat records an authenticated heartbeat (R11). With a digest it upserts
// only last_seen_at, credential_id and the heartbeat_* columns (a new row keeps an empty
// reported status; over the cap it is silently skipped with a warning). Without a digest (an
// old agent, or mode off) it only updates last_seen_at of an existing row and never inserts,
// so old agents' per-reload random instance ids never flood the table.
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
	err := s.upsert(ctx, row, []string{"last_seen_at", "credential_id", "heartbeat_config_revision", "heartbeat_config_digest", "updated_at"})
	if errors.Is(err, ErrInstanceLimit) {
		s.logger.Warnw("Agent instance cap reached; heartbeat not recorded as a new instance",
			"agentID", agentID, "instanceID", instanceID, "max", s.settings.MaxInstancesPerAgent)
		return nil
	}
	return err
}

// upsert updates the instance row when it exists, else inserts it after the cap check under
// a lock on the agent row (so concurrent first reports cannot overshoot the cap).
func (s *Service) upsert(ctx context.Context, row *relational.AgentInstance, columns []string) error {
	db := s.db.WithContext(ctx)
	updates := map[string]any{}
	for _, c := range columns {
		updates[c] = columnValue(row, c)
	}
	res := db.Model(&relational.AgentInstance{}).
		Where("agent_id = ? AND instance_id = ?", row.AgentID, row.InstanceID).
		Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var agent relational.Agent
		if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Select("id").Where("id = ?", row.AgentID).Take(&agent).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		count, err := s.countActiveInstances(tx, row.AgentID, row.LastSeenAt)
		if err != nil {
			return err
		}
		if count >= int64(s.settings.MaxInstancesPerAgent) {
			return ErrInstanceLimit
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "agent_id"}, {Name: "instance_id"}},
			DoUpdates: clause.AssignmentColumns(columns),
		}).Create(row).Error
	})
}

// countActiveInstances counts the instances that are not eligible for pruning (R37).
// "daemon IS FALSE" (not "daemon = false") keeps unknown-daemon rows counted like daemon
// rows, as PruneInstances keeps them: with "= false" a NULL daemon makes the NOT(...) NULL
// and the row silently drops out of the count.
func (s *Service) countActiveInstances(tx *gorm.DB, agentID uuid.UUID, now time.Time) (int64, error) {
	var count int64
	err := tx.Model(&relational.AgentInstance{}).
		Where("agent_id = ?", agentID).
		Where("NOT ((daemon IS FALSE AND last_seen_at < ?) OR last_seen_at < ?)",
			now.Add(-s.settings.OneShotInstanceRetention), now.Add(-s.settings.InstanceRetention)).
		Count(&count).Error
	return count, err
}

func columnValue(row *relational.AgentInstance, column string) any {
	switch column {
	case "credential_id":
		return row.CredentialID
	case "hostname":
		return row.Hostname
	case "agent_version":
		return row.AgentVersion
	case "mode":
		return row.Mode
	case "daemon":
		return row.Daemon
	case "last_seen_at":
		return row.LastSeenAt
	case "reported_at":
		return row.ReportedAt
	case "applied_revision":
		return row.AppliedRevision
	case "attempted_revision":
		return row.AttemptedRevision
	case "reported_status":
		return row.ReportedStatus
	case "apply_reason":
		return row.ApplyReason
	case "apply_error":
		return row.ApplyError
	case "truncated":
		return row.Truncated
	case "warnings":
		return row.Warnings
	case "base_config":
		return row.BaseConfig
	case "effective_config":
		return row.EffectiveConfig
	case "effective_digest":
		return row.EffectiveDigest
	case "remote_config":
		return row.RemoteConfig
	case "policy_bundles":
		return row.PolicyBundles
	case "policy_errors":
		return row.PolicyErrors
	case "unsafe_changes":
		return row.UnsafeChanges
	case "heartbeat_config_revision":
		return row.HeartbeatConfigRevision
	case "heartbeat_config_digest":
		return row.HeartbeatConfigDigest
	case "updated_at":
		return row.UpdatedAt
	default:
		panic("agentcfg: unknown instance column " + column)
	}
}

// summaryColumns are the instance columns loaded for list views (no base/effective/bundles).
var summaryColumns = []string{
	"id", "created_at", "updated_at", "agent_id", "instance_id", "credential_id",
	"hostname", "agent_version", "mode", "daemon", "first_seen_at", "last_seen_at",
	"reported_at", "applied_revision", "attempted_revision", "reported_status",
	"apply_reason", "apply_error", "truncated", "warnings", "effective_digest",
	"remote_config", "policy_errors", "unsafe_changes",
	"heartbeat_config_revision", "heartbeat_config_digest",
}

// ListInstances returns an agent's instances (most recently seen first) without the heavy
// base/effective/policy-bundle columns.
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

// baseColumns are the instance columns validation and preview need (no report payloads
// besides the base), so loading every instance of a large fleet stays cheap.
var baseColumns = []string{
	"id", "agent_id", "instance_id", "hostname", "mode", "daemon", "first_seen_at", "last_seen_at",
	"reported_at", "applied_revision", "attempted_revision", "reported_status",
	"base_config", "remote_config",
}

// InstanceBase is a reported base an overlay is validated or previewed against.
type InstanceBase struct {
	Instance  relational.AgentInstance
	Base      agentconfig.Config
	Remote    agentconfig.RemoteConfig // reported remote-config, or the base's block normalized with hasAuth=true
	Stale     bool
	Validated bool // member of ValidationBases (R48)
}

var applyModes = []string{agentconfig.ModeApplySafe, agentconfig.ModeApplyAll}

// ValidationBases is exactly the set PUT and revert validate against (R14, R48):
//  1. all fresh instances (seen within InstanceStaleAfter) with a reported base and an
//     apply mode;
//  2. else the single most recently reported instance with a base and an apply mode,
//     whatever its age;
//  3. else none, and standalone=true (overlay-level checks only).
//
// Report-mode instances and instances without a base are never validated against. A base
// that no longer decodes is skipped with a warning.
func (s *Service) ValidationBases(ctx context.Context, agentID uuid.UUID) ([]InstanceBase, bool, error) {
	now := s.now()
	var fresh []relational.AgentInstance
	err := s.db.WithContext(ctx).
		Select(baseColumns).
		Where("agent_id = ? AND base_config IS NOT NULL AND mode IN ? AND last_seen_at >= ?", agentID, applyModes, now.Add(-s.settings.InstanceStaleAfter)).
		Order("last_seen_at DESC, instance_id").
		Find(&fresh).Error
	if err != nil {
		return nil, false, err
	}
	rows := fresh
	if len(rows) == 0 {
		var latest []relational.AgentInstance
		err := s.db.WithContext(ctx).
			Select(baseColumns).
			Where("agent_id = ? AND base_config IS NOT NULL AND mode IN ? AND reported_at IS NOT NULL", agentID, applyModes).
			Order("reported_at DESC, instance_id").
			Limit(1).
			Find(&latest).Error
		if err != nil {
			return nil, false, err
		}
		rows = latest
	}
	bases := s.toBases(rows, now, true)
	return bases, len(bases) == 0, nil
}

// PreviewBases returns every instance with a reported base (fresh and stale, flagged), each
// marked Validated when it is in ValidationBases.
func (s *Service) PreviewBases(ctx context.Context, agentID uuid.UUID) ([]InstanceBase, error) {
	validation, _, err := s.ValidationBases(ctx, agentID)
	if err != nil {
		return nil, err
	}
	validated := map[uuid.UUID]bool{}
	for _, b := range validation {
		validated[b.Instance.InstanceID] = true
	}
	var rows []relational.AgentInstance
	if err := s.db.WithContext(ctx).
		Select(append(append([]string{}, baseColumns...), "effective_config")).
		Where("agent_id = ? AND base_config IS NOT NULL", agentID).
		Order("last_seen_at DESC, instance_id").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	bases := s.toBases(rows, s.now(), false)
	for i := range bases {
		bases[i].Validated = validated[bases[i].Instance.InstanceID]
	}
	return bases, nil
}

func (s *Service) toBases(rows []relational.AgentInstance, now time.Time, validated bool) []InstanceBase {
	out := make([]InstanceBase, 0, len(rows))
	for _, row := range rows {
		base, err := agentconfig.DecodeConfig(row.BaseConfig)
		if err != nil {
			s.logger.Warnw("Skipping agent instance with an undecodable reported base",
				"agentID", row.AgentID, "instanceID", row.InstanceID, "error", err)
			continue
		}
		out = append(out, InstanceBase{
			Instance:  row,
			Base:      base,
			Remote:    reportedRemote(row, base),
			Stale:     IsStale(row, now, s.settings),
			Validated: validated,
		})
	}
	return out
}

// reportedRemote returns the instance's reported remote-config block, or the base's block
// normalized with hasAuth=true (the base is redacted, so it has no client secret).
func reportedRemote(row relational.AgentInstance, base agentconfig.Config) agentconfig.RemoteConfig {
	var rc agentconfig.RemoteConfig
	if len(row.RemoteConfig) > 0 && string(row.RemoteConfig) != "null" {
		if err := json.Unmarshal(row.RemoteConfig, &rc); err == nil {
			if rc.Mode == "" {
				rc.Mode = row.Mode
			}
			return rc.Normalize(true)
		}
	}
	if base.RemoteConfig != nil {
		rc = *base.RemoteConfig
	}
	if rc.Mode == "" {
		rc.Mode = row.Mode
	}
	return rc.Normalize(true)
}

// DeleteInstancesForAgent removes every instance of an agent (agent deletion). Revisions
// are kept.
func DeleteInstancesForAgent(tx *gorm.DB, agentID uuid.UUID) error {
	return tx.Where("agent_id = ?", agentID).Delete(&relational.AgentInstance{}).Error
}

// PruneInstances deletes one-shot instances (daemon=false) not seen for
// OneShotInstanceRetention and any instance not seen for InstanceRetention (R37).
func PruneInstances(ctx context.Context, db *gorm.DB, s Settings, now time.Time) (int64, error) {
	s = s.WithDefaults()
	res := db.WithContext(ctx).
		Where("(daemon = false AND last_seen_at < ?) OR last_seen_at < ?",
			now.Add(-s.OneShotInstanceRetention), now.Add(-s.InstanceRetention)).
		Delete(&relational.AgentInstance{})
	return res.RowsAffected, res.Error
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
