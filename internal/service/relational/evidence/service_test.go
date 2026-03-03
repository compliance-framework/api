package evidence

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newEvidenceServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.Evidence{},
		&relational.Labels{},
		&relational.BackMatter{},
		&relational.BackMatterResource{},
	))
	return db
}

func TestEvidenceService_Create_WithLabels(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil)

	evidenceID := internal.Pointer(uuid.New())
	streamUUID := uuid.New()
	now := time.Now().UTC()

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUIDModel: relational.UUIDModel{ID: evidenceID},
			UUID:      streamUUID,
			Title:     "SSH password auth enabled",
			Start:     now.Add(-time.Hour),
			End:       now.Add(-time.Minute),
			Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied", Reason: "fail"}),
		},
		Labels: []relational.Labels{
			{Name: "provider", Value: "aws"},
			{Name: "service", Value: "ec2"},
		},
	}

	result, err := svc.Create(params)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, evidenceID, result.ID)
	require.Equal(t, streamUUID, result.UUID)

	var count int64
	require.NoError(t, db.Model(&relational.Evidence{}).Count(&count).Error)
	require.Equal(t, int64(1), count)

	var labelCount int64
	require.NoError(t, db.Model(&relational.Labels{}).Count(&labelCount).Error)
	require.Equal(t, int64(2), labelCount)

	var linkCount int64
	require.NoError(t, db.Table("evidence_labels").Count(&linkCount).Error)
	require.Equal(t, int64(2), linkCount)
}

func TestEvidenceService_Create_AutoSetsExpiry(t *testing.T) {
	db := newEvidenceServiceTestDB(t)

	// cfg with 3 months expiry
	svc := NewEvidenceService(db, &config.Config{EvidenceDefaultExpiryMonths: 3})

	now := time.Now().UTC()
	end := now.Add(-time.Minute)

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:  uuid.New(),
			Title: "test",
			Start: now.Add(-time.Hour),
			End:   end,
		},
	}

	result, err := svc.Create(params)
	require.NoError(t, err)
	require.NotNil(t, result.Expires)
	expected := end.AddDate(0, 3, 0)
	require.WithinDuration(t, expected, *result.Expires, time.Second)
}

func TestEvidenceService_Create_PreservesExplicitExpiry(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, &config.Config{EvidenceDefaultExpiryMonths: 3})

	now := time.Now().UTC()
	explicitExpiry := now.Add(90 * 24 * time.Hour)

	params := CreateEvidenceParams{
		Evidence: relational.Evidence{
			UUID:    uuid.New(),
			Title:   "test",
			Start:   now.Add(-time.Hour),
			End:     now.Add(-time.Minute),
			Expires: &explicitExpiry,
		},
	}

	result, err := svc.Create(params)
	require.NoError(t, err)
	require.NotNil(t, result.Expires)
	require.WithinDuration(t, explicitExpiry, *result.Expires, time.Second)
}

func TestEvidenceService_Create_DuplicateLabelsAreIdempotent(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil)

	label := relational.Labels{Name: "env", Value: "prod"}

	// First evidence
	_, err := svc.Create(CreateEvidenceParams{
		Evidence: relational.Evidence{UUID: uuid.New(), Title: "e1", Start: time.Now().Add(-time.Hour), End: time.Now()},
		Labels:   []relational.Labels{label},
	})
	require.NoError(t, err)

	// Second evidence with same label - label upsert should not fail
	_, err = svc.Create(CreateEvidenceParams{
		Evidence: relational.Evidence{UUID: uuid.New(), Title: "e2", Start: time.Now().Add(-time.Hour), End: time.Now()},
		Labels:   []relational.Labels{label},
	})
	require.NoError(t, err)

	var labelCount int64
	require.NoError(t, db.Model(&relational.Labels{}).Count(&labelCount).Error)
	require.Equal(t, int64(1), labelCount)

	var evidenceCount int64
	require.NoError(t, db.Model(&relational.Evidence{}).Count(&evidenceCount).Error)
	require.Equal(t, int64(2), evidenceCount)
}

func TestEvidenceService_GetByID(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil)

	id := internal.Pointer(uuid.New())
	now := time.Now().UTC()

	evidence := relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: id},
		UUID:      uuid.New(),
		Title:     "get-by-id test",
		Start:     now.Add(-time.Hour),
		End:       now.Add(-time.Minute),
	}
	require.NoError(t, db.Create(&evidence).Error)

	result, err := svc.GetByID(*id)
	require.NoError(t, err)
	require.Equal(t, id, result.ID)
	require.Equal(t, "get-by-id test", result.Title)
}

func TestEvidenceService_GetByID_NotFound(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil)

	_, err := svc.GetByID(uuid.New())
	require.Error(t, err)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestEvidenceService_GetHistory(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil)

	streamUUID := uuid.New()
	now := time.Now().UTC()

	evidences := []relational.Evidence{
		{
			UUID:  streamUUID,
			Title: "newest",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "older",
			Start: now.Add(-12 * time.Minute),
			End:   now.Add(-10 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "oldest",
			Start: now.Add(-22 * time.Minute),
			End:   now.Add(-20 * time.Minute),
		},
	}
	require.NoError(t, db.Create(&evidences).Error)

	results, err := svc.GetHistory(streamUUID)
	require.NoError(t, err)
	require.Len(t, results, 3)
	// Ordered by end DESC
	require.Equal(t, "newest", results[0].Title)
	require.Equal(t, "older", results[1].Title)
	require.Equal(t, "oldest", results[2].Title)
}

func TestEvidenceService_GetHistory_EmptyForUnknownStream(t *testing.T) {
	db := newEvidenceServiceTestDB(t)
	svc := NewEvidenceService(db, nil)

	results, err := svc.GetHistory(uuid.New())
	require.NoError(t, err)
	require.Empty(t, results)
}

