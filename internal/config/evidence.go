package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const DefaultEvidenceBadgeMaxParams = 3

func LoadEvidenceBadgeMaxParamsFromViper(v *viper.Viper) (int, error) {
	if !v.IsSet("evidence_badge_max_params") {
		return DefaultEvidenceBadgeMaxParams, nil
	}
	raw := strings.TrimSpace(v.GetString("evidence_badge_max_params"))
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("CCF_EVIDENCE_BADGE_MAX_PARAMS must be a positive integer, got %q", raw)
	}
	return value, nil
}

// EvidenceRequireSubjectMode is how agent evidence without a derived subject is handled
// (CCF_EVIDENCE_REQUIRE_SUBJECT).
type EvidenceRequireSubjectMode string

const (
	EvidenceRequireSubjectOff     EvidenceRequireSubjectMode = "off"
	EvidenceRequireSubjectWarn    EvidenceRequireSubjectMode = "warn"
	EvidenceRequireSubjectEnforce EvidenceRequireSubjectMode = "enforce"
)

// EvidenceSubjectConfig holds the evidence subject requirements.
type EvidenceSubjectConfig struct {
	// RequireSubject applies to agent evidence (CCF_EVIDENCE_REQUIRE_SUBJECT, default off).
	RequireSubject EvidenceRequireSubjectMode
	// ManualRequireSubject requires user-submitted evidence to name a subject
	// (CCF_MANUAL_EVIDENCE_REQUIRE_SUBJECT, default false).
	ManualRequireSubject bool
}

func LoadEvidenceSubjectConfig() (*EvidenceSubjectConfig, error) {
	return LoadEvidenceSubjectConfigFromViper(viper.GetViper())
}

func LoadEvidenceSubjectConfigFromViper(v *viper.Viper) (*EvidenceSubjectConfig, error) {
	mode := EvidenceRequireSubjectMode(strings.ToLower(strings.TrimSpace(v.GetString("evidence_require_subject"))))
	switch mode {
	case "":
		mode = EvidenceRequireSubjectOff
	case EvidenceRequireSubjectOff, EvidenceRequireSubjectWarn, EvidenceRequireSubjectEnforce:
	default:
		return nil, fmt.Errorf("CCF_EVIDENCE_REQUIRE_SUBJECT must be one of off, warn or enforce, got %q", mode)
	}

	return &EvidenceSubjectConfig{
		RequireSubject:       mode,
		ManualRequireSubject: v.GetBool("manual_evidence_require_subject"),
	}, nil
}

const (
	DefaultEvidenceBatchMaxItems  = 1000
	DefaultEvidenceBatchChunkSize = 100
	DefaultEvidenceBatchWorkers   = 4
	// DefaultEvidenceBatchRetention is how long batches are kept after they are accepted.
	DefaultEvidenceBatchRetention = 7 * 24 * time.Hour
	// DefaultEvidenceBatchPruneSchedule runs the batch prune job hourly (River 6-field cron).
	DefaultEvidenceBatchPruneSchedule = "0 47 * * * *"
)

// EvidenceBatchConfig bounds asynchronous batch evidence ingest (POST /api/evidence/batches).
type EvidenceBatchConfig struct {
	// MaxItems is the most evidence one batch may hold (CCF_EVIDENCE_BATCH_MAX_ITEMS).
	MaxItems int
	// ChunkSize is how many items one background job processes (CCF_EVIDENCE_BATCH_CHUNK_SIZE).
	ChunkSize int
	// Workers is how many chunks are processed at once (CCF_EVIDENCE_BATCH_WORKERS).
	Workers int
	// Retention is how long a batch and its item outcomes are kept after it was
	// accepted (CCF_EVIDENCE_BATCH_RETENTION, a Go duration). The evidence itself stays.
	Retention time.Duration
	// PruneSchedule is the River cron of the job deleting batches older than Retention
	// (CCF_EVIDENCE_BATCH_PRUNE_SCHEDULE).
	PruneSchedule string
}

func LoadEvidenceBatchConfig() (*EvidenceBatchConfig, error) {
	return LoadEvidenceBatchConfigFromViper(viper.GetViper())
}

func LoadEvidenceBatchConfigFromViper(v *viper.Viper) (*EvidenceBatchConfig, error) {
	cfg := &EvidenceBatchConfig{
		MaxItems:      DefaultEvidenceBatchMaxItems,
		ChunkSize:     DefaultEvidenceBatchChunkSize,
		Workers:       DefaultEvidenceBatchWorkers,
		Retention:     DefaultEvidenceBatchRetention,
		PruneSchedule: DefaultEvidenceBatchPruneSchedule,
	}
	for _, setting := range []struct {
		key, env string
		target   *int
	}{
		{"evidence_batch_max_items", "CCF_EVIDENCE_BATCH_MAX_ITEMS", &cfg.MaxItems},
		{"evidence_batch_chunk_size", "CCF_EVIDENCE_BATCH_CHUNK_SIZE", &cfg.ChunkSize},
		{"evidence_batch_workers", "CCF_EVIDENCE_BATCH_WORKERS", &cfg.Workers},
	} {
		if !v.IsSet(setting.key) {
			continue
		}
		value := v.GetInt(setting.key)
		if value <= 0 {
			return nil, fmt.Errorf("%s must be a positive integer, got %q", setting.env, v.GetString(setting.key))
		}
		*setting.target = value
	}
	if v.IsSet("evidence_batch_retention") {
		raw := strings.TrimSpace(v.GetString("evidence_batch_retention"))
		retention, err := time.ParseDuration(raw)
		if err != nil || retention <= 0 {
			return nil, fmt.Errorf("CCF_EVIDENCE_BATCH_RETENTION must be a positive duration such as 168h, got %q", raw)
		}
		cfg.Retention = retention
	}
	if schedule := strings.TrimSpace(v.GetString("evidence_batch_prune_schedule")); schedule != "" {
		cfg.PruneSchedule = schedule
	}
	return cfg, nil
}
