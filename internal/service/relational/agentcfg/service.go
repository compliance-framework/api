// Package agentcfg stores and serves agent remote-configuration revisions (append-only
// overlays per agent) and the agent instances that report against them.
package agentcfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
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
	MaxInstancesPerAgent     int           // non-prunable instances per agent; the oldest stale one is replaced when full
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
	return &Service{
		db:       db,
		settings: s.WithDefaults(),
		logger:   logger,
		now:      func() time.Time { return time.Now().UTC() },
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

// DeleteRevisionsForAgent removes every configuration revision of an agent (agent deletion).
// It is the purge path for an overlay that held a secret, so it bypasses the append-only
// BeforeDelete hook, which still blocks every other delete of a revision.
func DeleteRevisionsForAgent(tx *gorm.DB, agentID uuid.UUID) error {
	return tx.Session(&gorm.Session{SkipHooks: true}).
		Where("agent_id = ?", agentID).
		Delete(&relational.AgentConfigRevision{}).Error
}
