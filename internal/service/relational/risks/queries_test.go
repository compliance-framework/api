package risks

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMapSortField(t *testing.T) {
	require.Equal(t, "risk_register_risks.created_at", mapSortField("createdAt"))
	require.Equal(t, "risk_register_risks.updated_at", mapSortField("updatedAt"))
	require.Equal(t, "risk_register_risks.status", mapSortField("status"))
	require.Equal(t, "risk_register_risks.review_deadline", mapSortField("reviewDeadline"))
	require.Equal(t, "risk_register_risks.first_seen_at", mapSortField("firstSeenAt"))
	require.Equal(t, "risk_register_risks.last_seen_at", mapSortField("lastSeenAt"))
	require.Equal(t, "risk_register_risks.created_at", mapSortField("unknown"))
}

func TestCCFPropsAdapterRoundTrip(t *testing.T) {
	ownerID := uuid.New()
	nextReview := time.Now().UTC().Truncate(time.Second)
	justification := "approved"
	level := "high"
	r := Risk{
		Likelihood:              &level,
		Impact:                  &level,
		PrimaryOwnerUserID:      &ownerID,
		ReviewDeadline:          &nextReview,
		AcceptanceJustification: &justification,
	}
	props := BuildCCFOscalProps(r)
	require.NotEmpty(t, props)

	out := &Risk{}
	ApplyCCFPropsToRisk(props, out)
	require.NotNil(t, out.Likelihood)
	require.Equal(t, level, *out.Likelihood)
	require.NotNil(t, out.PrimaryOwnerUserID)
	require.Equal(t, ownerID, *out.PrimaryOwnerUserID)
	require.NotNil(t, out.ReviewDeadline)
	require.Equal(t, nextReview.Format(time.RFC3339), out.ReviewDeadline.UTC().Format(time.RFC3339))
	require.NotNil(t, out.AcceptanceJustification)
	require.Equal(t, justification, *out.AcceptanceJustification)

	ApplyCCFPropsToRisk([]oscalTypes_1_1_3.Property{{Name: "x", Ns: "other", Value: "y"}}, out)
}

func TestFromOSCALSetsSourceType(t *testing.T) {
	in := oscalTypes_1_1_3.Risk{
		UUID:        uuid.NewString(),
		Title:       "Imported risk",
		Description: "desc",
		Status:      string(RiskStatusOpen),
	}

	out := (&Risk{}).FromOSCAL(in)
	require.Equal(t, string(RiskSourceTypeOscalImport), out.SourceType)
}

func TestToOSCALIncludesFallbackStatementAndProps(t *testing.T) {
	id := uuid.New()
	level := string(RiskLevelMedium)
	ownerID := uuid.New()
	reviewDeadline := time.Now().UTC().Truncate(time.Second)
	justification := "accepted for 90 days"

	r := Risk{
		UUIDModel:               relational.UUIDModel{ID: &id},
		Title:                   "Imported from scanner",
		Status:                  string(RiskStatusOpen),
		Likelihood:              &level,
		Impact:                  &level,
		PrimaryOwnerUserID:      &ownerID,
		ReviewDeadline:          &reviewDeadline,
		AcceptanceJustification: &justification,
	}

	out := r.ToOSCAL()
	require.Equal(t, id.String(), out.UUID)
	require.Equal(t, r.Title, out.Statement)
	require.NotNil(t, out.Props)
	require.GreaterOrEqual(t, len(*out.Props), 5)
}

func TestFromOSCALDescriptionFallbackAndProps(t *testing.T) {
	ownerID := uuid.New()
	props := []oscalTypes_1_1_3.Property{
		{Name: CCFPropLikelihood, Ns: CCFPropsNamespace, Value: string(RiskLevelHigh)},
		{Name: CCFPropImpact, Ns: CCFPropsNamespace, Value: string(RiskLevelLow)},
		{Name: CCFPropPrimaryOwnerUserID, Ns: CCFPropsNamespace, Value: ownerID.String()},
	}

	in := oscalTypes_1_1_3.Risk{
		UUID:      uuid.NewString(),
		Title:     "Risk from OSCAL",
		Statement: "statement fallback",
		Status:    string(RiskStatusInvestigating),
		Props:     &props,
	}

	out := (&Risk{}).FromOSCAL(in)
	require.Equal(t, "statement fallback", out.Description)
	require.Equal(t, string(RiskStatusInvestigating), out.Status)
	require.Equal(t, string(RiskSourceTypeOscalImport), out.SourceType)
	require.NotNil(t, out.Likelihood)
	require.Equal(t, string(RiskLevelHigh), *out.Likelihood)
	require.NotNil(t, out.Impact)
	require.Equal(t, string(RiskLevelLow), *out.Impact)
	require.NotNil(t, out.PrimaryOwnerUserID)
	require.Equal(t, ownerID, *out.PrimaryOwnerUserID)
}

func TestApplyRiskFilters(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&Risk{}, &RiskOwnerAssignment{}, &RiskControlLink{}, &RiskEvidenceLink{}, &testEvidenceQueryRow{}))
	require.NoError(t, EnsureIndexes(db))

	sspA := uuid.New()
	sspB := uuid.New()
	ownerRef := "user-1"
	controlCatalogID := uuid.New()
	evidenceID := uuid.New()
	now := time.Now().UTC()

	medium := string(RiskLevelMedium)
	moderate := string(RiskLevelModerate)
	high := string(RiskLevelHigh)
	low := string(RiskLevelLow)

	riskA := Risk{
		Title:          "A",
		Description:    "A",
		Status:         string(RiskStatusOpen),
		SSPID:          sspA,
		Likelihood:     &medium,
		Impact:         &high,
		ReviewDeadline: ptrTime(now.Add(24 * time.Hour)),
		SourceType:     string(RiskSourceTypeManual),
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}
	riskB := Risk{
		Title:       "B",
		Description: "B",
		Status:      string(RiskStatusClosed),
		SSPID:       sspB,
		Likelihood:  &low,
		Impact:      &low,
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	riskC := Risk{
		Title:          "C",
		Description:    "C",
		Status:         string(RiskStatusOpen),
		SSPID:          sspA,
		Likelihood:     &low,
		Impact:         &medium,
		ReviewDeadline: ptrTime(now.Add(72 * time.Hour)),
		SourceType:     string(RiskSourceTypeManual),
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}

	require.NoError(t, db.Create(&riskA).Error)
	require.NoError(t, db.Create(&riskB).Error)
	require.NoError(t, db.Create(&riskC).Error)
	require.NoError(t, db.Create(&RiskOwnerAssignment{RiskID: *riskA.ID, OwnerKind: "user", OwnerRef: ownerRef, IsPrimary: true}).Error)
	require.NoError(t, db.Create(&RiskOwnerAssignment{RiskID: *riskC.ID, OwnerKind: "team", OwnerRef: "secops", IsPrimary: false}).Error)
	require.NoError(t, db.Create(&RiskControlLink{RiskID: *riskA.ID, CatalogID: controlCatalogID, ControlID: "AC-1"}).Error)
	require.NoError(t, db.Create(&RiskEvidenceLink{RiskID: *riskC.ID, EvidenceID: evidenceID}).Error)

	t.Run("status filter", func(t *testing.T) {
		status := string(RiskStatusClosed)
		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{Status: &status}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskB.ID, *out[0].ID)
	})

	t.Run("ssp and likelihood filter", func(t *testing.T) {
		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{SSPID: &sspA, Likelihood: &medium}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskA.ID, *out[0].ID)
	})

	t.Run("review deadline before filter", func(t *testing.T) {
		before := now.Add(48 * time.Hour)
		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{ReviewDeadlineBefore: &before}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskA.ID, *out[0].ID)
	})

	t.Run("control filter", func(t *testing.T) {
		controlID := "AC-1"
		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{ControlID: &controlID}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskA.ID, *out[0].ID)
	})

	t.Run("evidence filter", func(t *testing.T) {
		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{EvidenceID: &evidenceID}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskC.ID, *out[0].ID)
	})

	t.Run("owner kind and ref filter", func(t *testing.T) {
		ownerKind := "user"
		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{OwnerKind: &ownerKind, OwnerRef: &ownerRef}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskA.ID, *out[0].ID)
	})

	t.Run("owner ref only filter", func(t *testing.T) {
		ref := "secops"
		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{OwnerRef: &ref}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskC.ID, *out[0].ID)
	})

	t.Run("moderate filter matches legacy medium rows", func(t *testing.T) {
		require.NoError(t, db.Model(&Risk{}).Where("id = ?", *riskA.ID).UpdateColumn("likelihood", string(RiskLevelMediumLegacy)).Error)

		var out []Risk
		require.NoError(t, ApplyRiskFilters(db, ListFilters{SSPID: &sspA, Likelihood: &moderate}).Find(&out).Error)
		require.Len(t, out, 1)
		require.Equal(t, *riskA.ID, *out[0].ID)
	})
}

func TestApplyRiskSorting(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&Risk{}))

	createdAtOld := time.Now().UTC().Add(-2 * time.Hour)
	createdAtNew := time.Now().UTC().Add(-time.Hour)

	oldRisk := Risk{
		Title:       "old",
		Description: "old",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
		CreatedAt:   createdAtOld,
	}
	newRisk := Risk{
		Title:       "new",
		Description: "new",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
		CreatedAt:   createdAtNew,
	}

	require.NoError(t, db.Create(&oldRisk).Error)
	require.NoError(t, db.Create(&newRisk).Error)

	var asc []Risk
	require.NoError(t, ApplyRiskSorting(db.Model(&Risk{}), "createdAt", "asc").Find(&asc).Error)
	require.Len(t, asc, 2)
	require.Equal(t, oldRisk.Title, asc[0].Title)

	var defaultDesc []Risk
	require.NoError(t, ApplyRiskSorting(db.Model(&Risk{}), "createdAt", "bad-order").Find(&defaultDesc).Error)
	require.Len(t, defaultDesc, 2)
	require.Equal(t, newRisk.Title, defaultDesc[0].Title)
}

func TestOwnerAssignmentUniqueness(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&Risk{}, &RiskOwnerAssignment{}))

	riskID := uuid.New()
	risk := Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "r",
		Description: "d",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&risk).Error)

	assignment := RiskOwnerAssignment{RiskID: *risk.ID, OwnerKind: "user", OwnerRef: "u-1", IsPrimary: true}
	require.NoError(t, db.Create(&assignment).Error)
	err = db.Create(&assignment).Error
	require.Error(t, err)
}

func ptrTime(v time.Time) *time.Time { return &v }

type testEvidenceQueryRow struct {
	ID   uuid.UUID `gorm:"type:uuid;primaryKey"`
	UUID uuid.UUID `gorm:"type:uuid;index"`
	End  time.Time
}

func (testEvidenceQueryRow) TableName() string { return "evidences" }
