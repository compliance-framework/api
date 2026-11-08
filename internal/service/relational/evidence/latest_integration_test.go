//go:build integration

package evidence

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// LatestEvidenceIntegrationSuite pins relational.LatestEvidenceQuery (skip scan +
// lateral pick) to the DISTINCT ON query it replaced on the dashboard paths.
type LatestEvidenceIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestLatestEvidenceIntegration(t *testing.T) {
	suite.Run(t, new(LatestEvidenceIntegrationSuite))
}

type latestLabelRow struct {
	EvidenceID  uuid.UUID
	LabelsName  string
	LabelsValue string
}

// seedVersionedStreams stores streams x versions evidence, one minute apart per version
// and oldest first, ending at base. Each version's state and "svc" label change, so the
// latest version at a point decides what a query sees. It returns the stream uuids.
func (suite *LatestEvidenceIntegrationSuite) seedVersionedStreams(streams, versions int, base time.Time) []uuid.UUID {
	evidences := make([]relational.Evidence, 0, streams*versions)
	labels := make([]latestLabelRow, 0, streams*versions)
	streamIDs := make([]uuid.UUID, 0, streams)
	for i := 0; i < streams; i++ {
		stream := uuid.New()
		streamIDs = append(streamIDs, stream)
		// Streams have between 1 and versions versions.
		n := 1 + i%versions
		for v := 0; v < n; v++ {
			id := uuid.New()
			end := base.Add(-time.Duration(n-1-v) * time.Minute).Add(-time.Duration(i) * time.Second)
			state := []string{"satisfied", "not-satisfied", "unknown"}[(i+v)%3]
			evidences = append(evidences, relational.Evidence{
				UUIDModel: relational.UUIDModel{ID: &id},
				UUID:      stream,
				Title:     fmt.Sprintf("stream %d v%d", i, v),
				Start:     end.Add(-time.Second),
				End:       end,
				Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: state}),
			})
			labels = append(labels, latestLabelRow{EvidenceID: id, LabelsName: "svc", LabelsValue: []string{"a", "b"}[(i+v)%2]})
		}
	}
	suite.Require().NoError(suite.DB.CreateInBatches(&evidences, 1000).Error)
	suite.Require().NoError(suite.DB.Exec("INSERT INTO labels (name, value) VALUES ('svc','a'), ('svc','b') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Table("evidence_labels").CreateInBatches(&labels, 1000).Error)
	return streamIDs
}

func latestIDs(db *gorm.DB, latest *gorm.DB) ([]string, error) {
	var ids []string
	err := db.Table("(?) as l", latest).Order("l.id").Pluck("l.id", &ids).Error
	return ids, err
}

// oldStatusCountsAtPoint is EvidenceService.GetStatusCountsAtPoint as it was, over
// GetLatestEvidenceStreamsQuery.
func oldStatusCountsAtPoint(db *gorm.DB, filter labelfilter.Filter, endBefore *time.Time) ([]StatusCount, error) {
	latest := relational.GetLatestEvidenceStreamsQuery(db.Session(&gorm.Session{}))
	if endBefore != nil {
		latest = latest.Where("evidences.end < ?", endBefore.UTC())
	}
	q, err := relational.GetEvidenceSearchByFilterQuery(latest, db, filter)
	if err != nil {
		return nil, err
	}
	var rows []StatusCount
	err = q.Model(&relational.Evidence{}).
		Select("count(DISTINCT uuid) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error
	return nonNilStatusCounts(rows), err
}

func sortedStatusCounts(rows []StatusCount) []StatusCount {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Status < rows[j].Status })
	return rows
}

// oldLatestStreamIDs is the latest evidence id per stream as LoadLatestEvidenceStreams
// computed it before the skip scan (SELECT DISTINCT uuid).
func oldLatestStreamIDs(db *gorm.DB) ([]string, error) {
	var ids []string
	err := db.Raw(`SELECT l.id FROM (SELECT DISTINCT uuid FROM evidences) u
		CROSS JOIN LATERAL (SELECT e.id FROM evidences e WHERE e.uuid = u.uuid ORDER BY e."end" DESC LIMIT 1) l
		ORDER BY l.id`).Scan(&ids).Error
	return ids, err
}

func newLatestStreamIDs(db *gorm.DB, componentID *uuid.UUID) ([]string, error) {
	streams, err := relational.LoadLatestEvidenceStreams(db, componentID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(streams))
	for _, stream := range streams {
		ids = append(ids, stream.ID.String())
	}
	sort.Strings(ids)
	return ids, nil
}

func (suite *LatestEvidenceIntegrationSuite) TestEmptyTable() {
	suite.Require().NoError(suite.Migrator.Refresh())

	ids, err := latestIDs(suite.DB, relational.LatestEvidenceQuery(suite.DB, relational.LatestEvidenceOptions{}))
	suite.Require().NoError(err)
	suite.Empty(ids)
	streams, err := relational.LoadLatestEvidenceStreams(suite.DB, nil)
	suite.Require().NoError(err)
	suite.Empty(streams)
}

func (suite *LatestEvidenceIntegrationSuite) TestMatchesDistinctOn() {
	suite.Require().NoError(suite.Migrator.Refresh())
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	streamIDs := suite.seedVersionedStreams(40, 5, base)
	svc := NewEvidenceService(suite.DB, zap.NewNop().Sugar(), suite.Config, nil)

	points := []*time.Time{nil}
	for _, d := range []time.Duration{30 * time.Second, 2 * time.Minute, 3*time.Minute + 15*time.Second, 24 * time.Hour} {
		at := base.Add(-d)
		points = append(points, &at)
	}
	filters := []labelfilter.Filter{
		{},
		{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "svc", Operator: "=", Value: "a"}}},
		{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "svc", Operator: "!=", Value: "a"}}},
	}

	for _, at := range points {
		label := "now"
		if at != nil {
			label = at.Format(time.RFC3339)
		}
		var oldLatest *gorm.DB = relational.GetLatestEvidenceStreamsQuery(suite.DB.Session(&gorm.Session{}))
		if at != nil {
			oldLatest = oldLatest.Where("evidences.end < ?", at.UTC())
		}
		oldIDs, err := latestIDs(suite.DB, oldLatest)
		suite.Require().NoError(err)
		newIDs, err := latestIDs(suite.DB, relational.LatestEvidenceQuery(suite.DB, relational.LatestEvidenceOptions{EndBefore: at}))
		suite.Require().NoError(err)
		suite.Equal(oldIDs, newIDs, "latest evidence at %s", label)

		for i, filter := range filters {
			want, err := oldStatusCountsAtPoint(suite.DB, filter, at)
			suite.Require().NoError(err)
			got, err := svc.GetStatusCountsAtPoint(context.Background(), filter, at)
			suite.Require().NoError(err)
			suite.Equal(sortedStatusCounts(want), sortedStatusCounts(got), "filter %d at %s", i, label)
		}
	}

	// One stream, as status-over-time by uuid reads it.
	for _, stream := range streamIDs[:5] {
		at := base.Add(-90 * time.Second)
		var oldRows []StatusCount
		q, err := relational.GetEvidenceSearchByFilterQuery(
			relational.GetLatestEvidenceStreamsQuery(suite.DB.Session(&gorm.Session{})).Where("uuid = ?", stream.String()).Where("evidences.end < ?", at),
			suite.DB, labelfilter.Filter{})
		suite.Require().NoError(err)
		suite.Require().NoError(q.Model(&relational.Evidence{}).Select("count(*) as count, status->>'state' as status").Group("status->>'state'").Scan(&oldRows).Error)
		got, err := svc.GetStatusCountsByUUIDAtPoint(stream, &at)
		suite.Require().NoError(err)
		suite.Equal(nonNilStatusCounts(oldRows), got, "stream %s", stream)
	}

	// Search sees the same latest evidence.
	for i, filter := range filters {
		results, err := svc.Search(filter)
		suite.Require().NoError(err)
		var oldResults []relational.Evidence
		q, err := relational.GetEvidenceSearchByFilterQuery(relational.GetLatestEvidenceStreamsQuery(suite.DB.Session(&gorm.Session{})), suite.DB, filter)
		suite.Require().NoError(err)
		suite.Require().NoError(q.Find(&oldResults).Error)
		suite.ElementsMatch(evidenceIDs(oldResults), evidenceIDs(results), "search filter %d", i)
		suite.NotEmpty(results)
	}

	// LoadLatestEvidenceStreams, all streams and on one component.
	oldIDs, err := oldLatestStreamIDs(suite.DB)
	suite.Require().NoError(err)
	newIDs, err := newLatestStreamIDs(suite.DB, nil)
	suite.Require().NoError(err)
	suite.Equal(oldIDs, newIDs)
	suite.Len(newIDs, 40)

	componentID := uuid.New()
	for _, id := range newIDs[:3] {
		suite.Require().NoError(suite.DB.Exec("INSERT INTO evidence_components (evidence_id, system_component_id) VALUES (?, ?)", id, componentID).Error)
	}
	onComponent, err := newLatestStreamIDs(suite.DB, &componentID)
	suite.Require().NoError(err)
	suite.Equal(newIDs[:3], onComponent)
}

func evidenceIDs(evidence []relational.Evidence) []string {
	ids := make([]string, 0, len(evidence))
	for _, e := range evidence {
		ids = append(ids, e.ID.String())
	}
	return ids
}

// TestScale logs the old and new cost of status-over-time (7 points) and of loading
// the latest streams over 2000 streams with up to 50 versions each, and checks both
// agree.
func (suite *LatestEvidenceIntegrationSuite) TestScale() {
	suite.Require().NoError(suite.Migrator.Refresh())
	base := time.Now().UTC().Truncate(time.Second)
	suite.seedVersionedStreams(2000, 50, base)
	// Statistics as autovacuum would keep them; without them the planner misjudges the
	// label EXISTS for both queries.
	suite.Require().NoError(suite.DB.Exec("ANALYZE").Error)
	svc := NewEvidenceService(suite.DB, zap.NewNop().Sugar(), suite.Config, nil)
	filter := labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "svc", Operator: "=", Value: "a"}}}

	var points []*time.Time
	points = append(points, nil)
	for _, d := range []time.Duration{10, 20, 30, 60, 120, 240} {
		at := base.Add(-d * time.Second)
		points = append(points, &at)
	}

	start := time.Now()
	var oldCounts [][]StatusCount
	for _, at := range points {
		rows, err := oldStatusCountsAtPoint(suite.DB, filter, at)
		suite.Require().NoError(err)
		oldCounts = append(oldCounts, sortedStatusCounts(rows))
	}
	oldElapsed := time.Since(start)

	start = time.Now()
	var newCounts [][]StatusCount
	for _, at := range points {
		rows, err := svc.GetStatusCountsAtPoint(context.Background(), filter, at)
		suite.Require().NoError(err)
		newCounts = append(newCounts, sortedStatusCounts(rows))
	}
	newElapsed := time.Since(start)
	suite.Equal(oldCounts, newCounts)
	suite.T().Logf("status at 7 points: DISTINCT ON %s, skip scan %s", oldElapsed, newElapsed)

	start = time.Now()
	oldIDs, err := oldLatestStreamIDs(suite.DB)
	suite.Require().NoError(err)
	oldElapsed = time.Since(start)
	start = time.Now()
	newIDs, err := newLatestStreamIDs(suite.DB, nil)
	suite.Require().NoError(err)
	newElapsed = time.Since(start)
	suite.Equal(oldIDs, newIDs)
	suite.T().Logf("latest streams: DISTINCT uuid %s, skip scan %s (incl. labels)", oldElapsed, newElapsed)
}
