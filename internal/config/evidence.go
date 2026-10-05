package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

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
