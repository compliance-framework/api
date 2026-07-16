package oscal

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// seedLeverageLinkForDrift creates the minimal graph applyDriftToLink/
// evaluateLeverageDriftForOffering need: an Export with one
// ProvidedControlImplementation and one ControlImplementationResponsibility under it,
// an upstream+downstream SSP, an SSPExportOffering, and an active SSPLeverageLink tying
// them together at offeringVersion.
func seedLeverageLinkForDrift(t *testing.T, db *gorm.DB, offeringVersion int) (*relational.SSPExportOffering, *relational.SSPLeverageLink, uuid.UUID) {
	t.Helper()

	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID}
	require.NoError(t, db.Create(&provided).Error)

	responsibility := relational.ControlImplementationResponsibility{ExportId: *export.ID, ProvidedUuid: *provided.ID}
	require.NoError(t, db.Create(&responsibility).Error)

	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)
	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)

	offering := relational.SSPExportOffering{
		SSPID: *upstreamSSP.ID, Title: "Offering", Status: relational.SSPExportOfferingStatusPublished, Version: offeringVersion,
	}
	require.NoError(t, db.Create(&offering).Error)

	link := relational.SSPLeverageLink{
		DownstreamSSPID:   *downstreamSSP.ID,
		UpstreamSSPID:     *upstreamSSP.ID,
		OfferingID:        *offering.ID,
		OfferingVersion:   1,
		ControlID:       "ac-1",
		ProvidedUUID:    *provided.ID,
		InheritedUUID:   uuid.New(),
		Satisfaction:    relational.SSPLeverageSatisfactionFull,
		Status:          relational.SSPLeverageStatusActive,
	}
	require.NoError(t, db.Create(&link).Error)

	return &offering, &link, *responsibility.ID
}

func TestApplyDriftToLinkCreatesRiskAndFlipsStatus(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	_, link, responsibilityUUID := seedLeverageLinkForDrift(t, db, 2)

	info, ok, err := applyDriftToLink(db, link, "upstream offering content changed")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, *link.ID, info.LinkID)
	require.Equal(t, link.DownstreamSSPID, info.DownstreamSSPID)

	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusDrifted, reloadedLink.Status)

	var risk risks.Risk
	require.NoError(t, db.First(&risk, "id = ?", info.RiskID).Error)
	require.Equal(t, string(risks.RiskSourceTypeInheritedRevoked), risk.SourceType)
	require.Equal(t, string(risks.RiskStatusOpen), risk.Status)
	require.Equal(t, link.DownstreamSSPID, risk.SSPID)

	var responsibilityLink risks.RiskResponsibilityLink
	require.NoError(t, db.Where("risk_id = ? AND responsibility_uuid = ?", risk.ID, responsibilityUUID).First(&responsibilityLink).Error)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Count(&riskCount).Error)
	require.Equal(t, int64(1), riskCount)
}

func TestApplyDriftToLinkIsNoOpWhenAlreadyDrifted(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	_, link, _ := seedLeverageLinkForDrift(t, db, 2)

	_, ok, err := applyDriftToLink(db, link, "first drift")
	require.NoError(t, err)
	require.True(t, ok)

	// link is now Drifted (in-memory struct updated by applyDriftToLink); calling again
	// on the same struct must be a no-op — no second risk, no re-flip.
	info, ok, err := applyDriftToLink(db, link, "second drift")
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, info)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Count(&riskCount).Error)
	require.Equal(t, int64(1), riskCount)
}

func TestApplyDriftToLinkReopensRemediatedRisk(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	_, link, _ := seedLeverageLinkForDrift(t, db, 2)

	info, _, err := applyDriftToLink(db, link, "first drift")
	require.NoError(t, err)

	// Simulate re-attestation clearing the risk and reactivating the link.
	require.NoError(t, db.Model(&risks.Risk{}).Where("id = ?", info.RiskID).Update("status", string(risks.RiskStatusRemediated)).Error)
	require.NoError(t, db.Model(&relational.SSPLeverageLink{}).Where("id = ?", link.ID).Update("status", relational.SSPLeverageStatusActive).Error)
	link.Status = relational.SSPLeverageStatusActive

	reInfo, ok, err := applyDriftToLink(db, link, "drifted again")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, info.RiskID, reInfo.RiskID)

	var risk risks.Risk
	require.NoError(t, db.First(&risk, "id = ?", info.RiskID).Error)
	require.Equal(t, string(risks.RiskStatusOpen), risk.Status)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Count(&riskCount).Error)
	require.Equal(t, int64(1), riskCount)
}

func TestEvaluateLeverageDriftForOfferingOnlyDriftsBehindLinks(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	offering, link, _ := seedLeverageLinkForDrift(t, db, 1)
	// link.OfferingVersion == 1, offering.Version == 1: up to date, must not drift.

	results, err := evaluateLeverageDriftForOffering(db, *offering)
	require.NoError(t, err)
	require.Empty(t, results)

	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusActive, reloadedLink.Status)
}

func TestEvaluateLeverageDriftForOfferingDriftsOnVersionBump(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	offering, link, _ := seedLeverageLinkForDrift(t, db, 2)
	// link.OfferingVersion == 1, offering.Version == 2: behind, must drift.

	results, err := evaluateLeverageDriftForOffering(db, *offering)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, *link.ID, results[0].LinkID)
}

func TestEvaluateLeverageDriftForOfferingDriftsOnDeprecated(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	offering, link, _ := seedLeverageLinkForDrift(t, db, 1)
	offering.Status = relational.SSPExportOfferingStatusDeprecated

	results, err := evaluateLeverageDriftForOffering(db, *offering)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, *link.ID, results[0].LinkID)
}

func TestResolveCatalogIDForControlResolvesFromDownstreamProfile(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)

	catalogID := uuid.New()
	control := relational.Control{CatalogID: catalogID, ID: "ac-1", Title: "Access Control"}
	require.NoError(t, db.Create(&control).Error)

	profile := relational.Profile{Controls: []relational.Control{control}}
	require.NoError(t, db.Create(&profile).Error)

	require.NoError(t, db.Create(&relational.SSPProfile{
		SystemSecurityPlanID: *downstreamSSP.ID, ProfileID: *profile.ID,
	}).Error)

	resolved, ok, err := resolveCatalogIDForControl(db, *downstreamSSP.ID, "AC-1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, catalogID, resolved)
}

func TestResolveCatalogIDForControlMissReturnsNotOK(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)

	_, ok, err := resolveCatalogIDForControl(db, *downstreamSSP.ID, "ac-1")
	require.NoError(t, err)
	require.False(t, ok)
}

// TestSameLinkDriftedByTwoTriggersInQuickSuccessionDoesNotDuplicateRisk: a link's dedupe
// key is per-link, not per-trigger — if a version-bump drift and a deprecate/revoke
// drift both land on the same link (e.g. a version bump processed just before an
// operator deprecates the offering), the second call must be a no-op rather than
// creating a second risk, since applyDriftToLink already skips non-active links.
func TestSameLinkDriftedByTwoTriggersInQuickSuccessionDoesNotDuplicateRisk(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	_, link, _ := seedLeverageLinkForDrift(t, db, 2)

	_, ok, err := applyDriftToLink(db, link, "upstream offering content changed")
	require.NoError(t, err)
	require.True(t, ok)

	// A second, differently-reasoned trigger arriving right after (e.g. deprecate) finds
	// the link already Drifted and must be a no-op.
	info, ok, err := applyDriftToLink(db, link, "upstream offering deprecated")
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, info)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Where("source_type = ?", string(risks.RiskSourceTypeInheritedRevoked)).Count(&riskCount).Error)
	require.Equal(t, int64(1), riskCount)
}
