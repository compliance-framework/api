package risks

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRiskBeforeCreateDefaults(t *testing.T) {
	r := &Risk{
		Title:       "Defaulted risk",
		Description: "desc",
		SSPID:       uuid.New(),
	}

	err := r.BeforeCreate(nil)
	require.NoError(t, err)
	require.NotNil(t, r.ID)
	require.Equal(t, string(RiskStatusOpen), r.Status)
	require.Equal(t, string(RiskSourceTypeManual), r.SourceType)
	require.False(t, r.FirstSeenAt.IsZero())
	require.False(t, r.LastSeenAt.IsZero())
}

func TestRiskBeforeCreatePreservesProvidedValues(t *testing.T) {
	id := uuid.New()
	firstSeen := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	lastSeen := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	level := string(RiskLevelHigh)

	r := &Risk{
		UUIDModel:   relational.UUIDModel{ID: &id},
		Title:       "Provided values",
		Description: "desc",
		SSPID:       uuid.New(),
		Status:      string(RiskStatusInvestigating),
		SourceType:  string(RiskSourceTypeEvidenceAuto),
		FirstSeenAt: firstSeen,
		LastSeenAt:  lastSeen,
		Likelihood:  &level,
		Impact:      &level,
	}

	err := r.BeforeCreate(nil)
	require.NoError(t, err)
	require.Equal(t, id, *r.ID)
	require.Equal(t, string(RiskStatusInvestigating), r.Status)
	require.Equal(t, string(RiskSourceTypeEvidenceAuto), r.SourceType)
	require.Equal(t, firstSeen, r.FirstSeenAt)
	require.Equal(t, lastSeen, r.LastSeenAt)
}

func TestRiskBeforeCreateValidationErrors(t *testing.T) {
	badLevel := "invalid-level"
	cases := []struct {
		name      string
		mutate    func(*Risk)
		errSubstr string
	}{
		{
			name: "invalid status",
			mutate: func(r *Risk) {
				r.Status = "not-a-status"
			},
			errSubstr: "invalid risk status",
		},
		{
			name: "invalid source type",
			mutate: func(r *Risk) {
				r.SourceType = "not-a-source"
			},
			errSubstr: "invalid risk source type",
		},
		{
			name: "invalid likelihood",
			mutate: func(r *Risk) {
				r.Likelihood = &badLevel
			},
			errSubstr: "invalid likelihood",
		},
		{
			name: "invalid impact",
			mutate: func(r *Risk) {
				r.Impact = &badLevel
			},
			errSubstr: "invalid impact",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Risk{
				Title:       "Validation risk",
				Description: "desc",
				SSPID:       uuid.New(),
			}
			tc.mutate(r)
			err := r.BeforeCreate(nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errSubstr)
		})
	}
}

func TestRiskBeforeCreateCanonicalizesLegacyMediumLevel(t *testing.T) {
	medium := "medium"
	r := &Risk{
		Title:       "Legacy medium normalization",
		Description: "desc",
		SSPID:       uuid.New(),
		Likelihood:  &medium,
		Impact:      &medium,
	}

	err := r.BeforeCreate(nil)
	require.NoError(t, err)
	require.NotNil(t, r.Likelihood)
	require.NotNil(t, r.Impact)
	require.Equal(t, string(RiskLevelModerate), *r.Likelihood)
	require.Equal(t, string(RiskLevelModerate), *r.Impact)
}

func TestNormalizeRiskLevel(t *testing.T) {
	require.Equal(t, RiskLevelModerate, NormalizeRiskLevel(" medium "))
	require.Equal(t, RiskLevelCritical, NormalizeRiskLevel("CRITICAL"))
	require.Equal(t, RiskLevel("invalid"), NormalizeRiskLevel("invalid"))
}
