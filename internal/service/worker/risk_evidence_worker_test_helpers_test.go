//go:build integration

package worker

import (
	"testing"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// seedLeveragedResponsibility creates the minimal real-schema graph a
// filter_responsibilities → ssp_leverage_links resolution needs: an Export with one
// ProvidedControlImplementation and one ControlImplementationResponsibility under it, an
// upstream and downstream SystemSecurityPlan, and an SSPLeverageLink tying the two
// together. Shared by RiskEvidenceWorkerResponsibilityIntegrationSuite (BCH-1339) and
// InheritedResponsibilityRiskIntegrationSuite (BCH-1340).
func seedLeveragedResponsibility(t *testing.T, db *gorm.DB) (responsibilityUUID, downstreamSSPID, upstreamSSPID uuid.UUID) {
	t.Helper()

	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided"}
	require.NoError(t, db.Create(&provided).Error)

	responsibility := relational.ControlImplementationResponsibility{
		ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "responsibility",
	}
	require.NoError(t, db.Create(&responsibility).Error)

	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)

	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)

	link := relational.SSPLeverageLink{
		DownstreamSSPID: *downstreamSSP.ID,
		UpstreamSSPID:   *upstreamSSP.ID,
		OfferingID:      uuid.New(),
		ControlID:       "ac-1",
		ProvidedUUID:    *provided.ID,
		InheritedUUID:   uuid.New(),
		Satisfaction:    relational.SSPLeverageSatisfactionPartial,
		Status:          relational.SSPLeverageStatusActive,
	}
	require.NoError(t, db.Create(&link).Error)

	return *responsibility.ID, *downstreamSSP.ID, *upstreamSSP.ID
}

// seedResponsibilityFilter creates a filter matching labelKey=labelValue and links it to
// responsibilityUUID, scoped to downstreamSSPID, via filter_responsibilities.
func seedResponsibilityFilter(t *testing.T, db *gorm.DB, downstreamSSPID, responsibilityUUID uuid.UUID, labelKey, labelValue string) {
	t.Helper()

	filterScope := labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Condition: &labelfilter.Condition{Label: labelKey, Operator: "=", Value: labelValue},
		},
	}
	f := relational.Filter{Name: "responsibility-filter", Filter: datatypes.NewJSONType(filterScope)}
	require.NoError(t, db.Create(&f).Error)
	require.NoError(t, db.Create(&relational.FilterResponsibility{
		FilterID:           *f.ID,
		ResponsibilityUUID: responsibilityUUID,
		SSPID:              downstreamSSPID,
	}).Error)
}
