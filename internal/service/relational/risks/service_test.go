package risks

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRiskServiceCreateUpdateDeleteAndAuditRetention(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	actorID := uuid.New()
	sspID := uuid.New()
	l := string(RiskLevelModerate)
	i := string(RiskLevelHigh)

	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "Service risk",
			Description: "created via service",
			Status:      string(RiskStatusInvestigating),
			SSPID:       sspID,
			Likelihood:  &l,
			Impact:      &i,
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		},
		OwnerAssignments: []RiskOwnerAssignment{{OwnerKind: "group", OwnerRef: "secops", IsPrimary: true}},
		ActorUserID:      &actorID,
	})
	require.NoError(t, err)
	require.NotNil(t, created.ID)
	require.Len(t, created.OwnerAssignments, 1)

	var createdEvents []RiskEvent
	require.NoError(t, db.Where("risk_id = ?", *created.ID).Find(&createdEvents).Error)
	require.Len(t, createdEvents, 1)
	require.Equal(t, string(RiskEventTypeCreated), createdEvents[0].EventType)
	require.NotEmpty(t, createdEvents[0].RiskSnapshot)
	require.NotNil(t, createdEvents[0].Details)
	require.NotEmpty(t, *createdEvents[0].Details)

	reviewDeadline := time.Now().UTC().Add(14 * 24 * time.Hour)
	acceptanceJustification := "accepted for limited period"
	reviewJustification := "quarterly review"
	updatedRisk := *created
	updatedRisk.Status = string(RiskStatusRiskAccepted)
	updatedRisk.ReviewDeadline = &reviewDeadline
	updatedRisk.AcceptanceJustification = &acceptanceJustification

	updated, err := svc.Update(UpdateRiskParams{
		Risk:                &updatedRisk,
		ActorUserID:         &actorID,
		OldStatus:           string(RiskStatusInvestigating),
		StatusChanged:       true,
		RecordReview:        true,
		ReviewJustification: &reviewJustification,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusRiskAccepted), updated.Status)

	var reviews []RiskReview
	require.NoError(t, db.Where("risk_id = ?", *created.ID).Find(&reviews).Error)
	require.Len(t, reviews, 1)
	require.NotNil(t, reviews[0].ReviewJustification)
	require.Equal(t, reviewJustification, *reviews[0].ReviewJustification)
	require.NotEmpty(t, reviews[0].RiskSnapshot)

	var events []RiskEvent
	require.NoError(t, db.Where("risk_id = ?", *created.ID).Find(&events).Error)
	eventTypes := make([]string, 0, len(events))
	for _, e := range events {
		eventTypes = append(eventTypes, e.EventType)
	}
	require.Contains(t, eventTypes, string(RiskEventTypeStatusChange))
	require.Contains(t, eventTypes, string(RiskEventTypeAccepted))
	require.Contains(t, eventTypes, string(RiskEventTypeReviewed))

	require.NoError(t, db.Create(&RiskEvidenceLink{RiskID: *created.ID, EvidenceID: uuid.New()}).Error)
	require.NoError(t, db.Create(&RiskControlLink{RiskID: *created.ID, CatalogID: uuid.New(), ControlID: "AC-1"}).Error)
	require.NoError(t, db.Create(&RiskComponentLink{RiskID: *created.ID, ComponentID: uuid.New()}).Error)
	require.NoError(t, db.Create(&RiskSubjectLink{RiskID: *created.ID, SubjectID: uuid.New()}).Error)

	require.NoError(t, svc.Delete(*created.ID))

	_, err = svc.GetByID(*created.ID)
	require.Error(t, err)
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound))

	var linkCount int64
	require.NoError(t, db.Model(&RiskEvidenceLink{}).Where("risk_id = ?", *created.ID).Count(&linkCount).Error)
	require.Zero(t, linkCount)
	require.NoError(t, db.Model(&RiskControlLink{}).Where("risk_id = ?", *created.ID).Count(&linkCount).Error)
	require.Zero(t, linkCount)
	require.NoError(t, db.Model(&RiskComponentLink{}).Where("risk_id = ?", *created.ID).Count(&linkCount).Error)
	require.Zero(t, linkCount)
	require.NoError(t, db.Model(&RiskSubjectLink{}).Where("risk_id = ?", *created.ID).Count(&linkCount).Error)
	require.Zero(t, linkCount)
	require.NoError(t, db.Model(&RiskOwnerAssignment{}).Where("risk_id = ?", *created.ID).Count(&linkCount).Error)
	require.Zero(t, linkCount)

	var retainedEvents int64
	require.NoError(t, db.Model(&RiskEvent{}).Where("risk_id = ?", *created.ID).Count(&retainedEvents).Error)
	require.Greater(t, retainedEvents, int64(0))
	var retainedReviews int64
	require.NoError(t, db.Model(&RiskReview{}).Where("risk_id = ?", *created.ID).Count(&retainedReviews).Error)
	require.Greater(t, retainedReviews, int64(0))

	err = svc.Delete(*created.ID)
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound))
}

func TestRiskServiceLinksAndAssociations(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "link-risk",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	evidenceID := uuid.New()
	evidenceStreamID := uuid.New()
	catalogID := uuid.New()
	componentID := uuid.New()
	subjectID := uuid.New()
	require.NoError(t, db.Create(&testEvidenceRow{ID: evidenceID, UUID: evidenceStreamID, End: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&testControlRow{CatalogID: catalogID, ID: "AC-2"}).Error)
	require.NoError(t, db.Create(&testSystemComponentRow{ID: componentID}).Error)
	require.NoError(t, db.Create(&testAssessmentSubjectRow{ID: subjectID}).Error)

	actorID := uuid.New()
	evidenceLink, err := svc.AddEvidenceLink(riskID, evidenceID, &actorID)
	require.NoError(t, err)
	require.False(t, evidenceLink.CreatedAt.IsZero())

	evidenceLink, err = svc.AddEvidenceLink(riskID, evidenceID, &actorID)
	require.NoError(t, err)
	require.False(t, evidenceLink.CreatedAt.IsZero())

	evidenceIDs, evidenceTotal, err := svc.ListEvidenceLinks(riskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), evidenceTotal)
	require.Len(t, evidenceIDs, 1)
	require.Equal(t, evidenceStreamID, evidenceIDs[0])

	deleted, err := svc.DeleteEvidenceLink(riskID, evidenceID, &actorID)
	require.NoError(t, err)
	require.True(t, deleted)
	deleted, err = svc.DeleteEvidenceLink(riskID, evidenceID, &actorID)
	require.NoError(t, err)
	require.False(t, deleted)
	_, err = svc.AddEvidenceLink(riskID, evidenceID, &actorID)
	require.NoError(t, err)

	controlLink, err := svc.AddControlLink(riskID, catalogID, "AC-2", &actorID)
	require.NoError(t, err)
	require.False(t, controlLink.CreatedAt.IsZero())

	controlLink, err = svc.AddControlLink(riskID, catalogID, "AC-2", &actorID)
	require.NoError(t, err)
	require.False(t, controlLink.CreatedAt.IsZero())

	controlLinks, controlTotal, err := svc.ListControlLinks(riskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), controlTotal)
	require.Len(t, controlLinks, 1)
	require.Equal(t, "AC-2", controlLinks[0].ControlID)

	componentLink, err := svc.AddComponentLink(riskID, componentID, &actorID)
	require.NoError(t, err)
	require.False(t, componentLink.CreatedAt.IsZero())

	componentLink, err = svc.AddComponentLink(riskID, componentID, &actorID)
	require.NoError(t, err)
	require.False(t, componentLink.CreatedAt.IsZero())

	componentLinks, componentTotal, err := svc.ListComponentLinks(riskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), componentTotal)
	require.Len(t, componentLinks, 1)
	require.Equal(t, componentID, componentLinks[0].ComponentID)

	subjectLink, err := svc.AddSubjectLink(riskID, subjectID, &actorID)
	require.NoError(t, err)
	require.False(t, subjectLink.CreatedAt.IsZero())

	subjectLink, err = svc.AddSubjectLink(riskID, subjectID, &actorID)
	require.NoError(t, err)
	require.False(t, subjectLink.CreatedAt.IsZero())

	subjectLinks, subjectTotal, err := svc.ListSubjectLinks(riskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), subjectTotal)
	require.Len(t, subjectLinks, 1)
	require.Equal(t, subjectID, subjectLinks[0].SubjectID)

	associations, err := svc.GetAssociations(riskID)
	require.NoError(t, err)
	require.Contains(t, associations.EvidenceIDs, evidenceStreamID)
	require.Contains(t, associations.ComponentIDs, componentID)
	require.Contains(t, associations.SubjectIDs, subjectID)
	require.Len(t, associations.ControlLinks, 1)
	require.Equal(t, "AC-2", associations.ControlLinks[0].ControlID)

	var evidenceEvents int64
	require.NoError(t, db.Model(&RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", riskID, string(RiskEventTypeEvidenceLink)).
		Count(&evidenceEvents).Error)
	require.Equal(t, int64(2), evidenceEvents)
}

func TestRiskServiceGetAssociationsByRiskIDs(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID1 := uuid.New()
	riskID2 := uuid.New()
	for _, riskID := range []uuid.UUID{riskID1, riskID2} {
		require.NoError(t, db.Create(&Risk{
			UUIDModel:   relational.UUIDModel{ID: &riskID},
			Title:       "batch-risk",
			Description: "desc",
			Status:      string(RiskStatusOpen),
			SSPID:       uuid.New(),
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		}).Error)
	}

	require.NoError(t, db.Create(&RiskEvidenceLink{RiskID: riskID1, EvidenceID: uuid.New()}).Error)
	require.NoError(t, db.Create(&RiskControlLink{RiskID: riskID1, CatalogID: uuid.New(), ControlID: "AC-1"}).Error)
	require.NoError(t, db.Create(&RiskComponentLink{RiskID: riskID2, ComponentID: uuid.New()}).Error)
	require.NoError(t, db.Create(&RiskSubjectLink{RiskID: riskID2, SubjectID: uuid.New()}).Error)

	batch, err := svc.GetAssociationsByRiskIDs([]uuid.UUID{riskID1, riskID2})
	require.NoError(t, err)
	require.Len(t, batch, 2)
	require.Len(t, batch[riskID1].EvidenceIDs, 1)
	require.Len(t, batch[riskID1].ControlLinks, 1)
	require.Len(t, batch[riskID1].ComponentIDs, 0)
	require.Len(t, batch[riskID1].SubjectIDs, 0)
	require.Len(t, batch[riskID2].EvidenceIDs, 0)
	require.Len(t, batch[riskID2].ControlLinks, 0)
	require.Len(t, batch[riskID2].ComponentIDs, 1)
	require.Len(t, batch[riskID2].SubjectIDs, 1)

	emptyBatch, err := svc.GetAssociationsByRiskIDs(nil)
	require.NoError(t, err)
	require.Empty(t, emptyBatch)
}

func TestRiskServiceListEventsAndReviews(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "history-risk",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	actorID := uuid.New()
	olderEventTime := time.Now().UTC().Add(-2 * time.Hour)
	newerEventTime := time.Now().UTC().Add(-time.Hour)
	olderReviewTime := time.Now().UTC().Add(-90 * time.Minute)
	newerReviewTime := time.Now().UTC().Add(-30 * time.Minute)

	require.NoError(t, db.Create(&RiskEvent{
		RiskID:      riskID,
		EventType:   string(RiskEventTypeCreated),
		ActorUserID: &actorID,
		OccurredAt:  olderEventTime,
		CreatedAt:   time.Now().UTC().Add(-10 * time.Minute),
	}).Error)
	require.NoError(t, db.Create(&RiskEvent{
		RiskID:      riskID,
		EventType:   string(RiskEventTypeReviewed),
		ActorUserID: &actorID,
		OccurredAt:  newerEventTime,
		CreatedAt:   time.Now().UTC().Add(-3 * time.Hour),
	}).Error)

	require.NoError(t, db.Create(&RiskReview{
		RiskID:           riskID,
		ReviewedByUserID: &actorID,
		ReviewedAt:       olderReviewTime,
		Decision:         string(RiskReviewDecisionExtend),
		CreatedAt:        time.Now().UTC().Add(-5 * time.Minute),
	}).Error)
	require.NoError(t, db.Create(&RiskReview{
		RiskID:           riskID,
		ReviewedByUserID: &actorID,
		ReviewedAt:       newerReviewTime,
		Decision:         string(RiskReviewDecisionReopen),
		CreatedAt:        time.Now().UTC().Add(-4 * time.Hour),
	}).Error)

	events, eventTotal, err := svc.ListEvents(riskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(2), eventTotal)
	require.Len(t, events, 2)
	require.Equal(t, string(RiskEventTypeReviewed), events[0].EventType)
	require.Equal(t, string(RiskEventTypeCreated), events[1].EventType)
	require.True(t, events[0].OccurredAt.After(events[1].OccurredAt))

	reviews, reviewTotal, err := svc.ListReviews(riskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(2), reviewTotal)
	require.Len(t, reviews, 2)
	require.Equal(t, string(RiskReviewDecisionReopen), reviews[0].Decision)
	require.Equal(t, string(RiskReviewDecisionExtend), reviews[1].Decision)
	require.True(t, reviews[0].ReviewedAt.After(reviews[1].ReviewedAt))

	pagedEvents, pagedEventTotal, err := svc.ListEvents(riskID, 1, 0)
	require.NoError(t, err)
	require.Equal(t, int64(2), pagedEventTotal)
	require.Len(t, pagedEvents, 1)

	otherRiskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &otherRiskID},
		Title:       "history-empty",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)
	emptyReviews, emptyReviewTotal, err := svc.ListReviews(otherRiskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(0), emptyReviewTotal)
	require.Empty(t, emptyReviews)
}

func TestRiskServiceUpdateStatusAndReviewUsesSingleRiskSnapshotLoad(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "snapshot-count-risk",
		Description: "desc",
		Status:      string(RiskStatusInvestigating),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	risk, err := svc.GetByID(riskID)
	require.NoError(t, err)
	risk.Status = string(RiskStatusRiskAccepted)
	deadline := time.Now().UTC().Add(24 * time.Hour)
	risk.ReviewDeadline = &deadline
	acceptance := "accepted for now"
	risk.AcceptanceJustification = &acceptance
	reviewJustification := "governance review"

	riskQueryCount := 0
	callbackName := "count_risk_snapshot_loads"
	require.NoError(t, db.Callback().Query().After("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "risk_register_risks" {
			riskQueryCount++
		}
	}))
	t.Cleanup(func() {
		_ = db.Callback().Query().Remove(callbackName)
	})

	_, err = svc.Update(UpdateRiskParams{
		Risk:                risk,
		OldStatus:           string(RiskStatusInvestigating),
		StatusChanged:       true,
		RecordReview:        true,
		ReviewJustification: &reviewJustification,
	})
	require.NoError(t, err)
	require.Equal(t, 2, riskQueryCount, fmt.Sprintf("expected one risk snapshot load plus final GetByID, got %d", riskQueryCount))
}

func TestRiskServiceResolveUserIDAndPrimaryValidation(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	userID := uuid.New()
	require.NoError(t, db.Create(&testUserRow{
		ID:    userID,
		Email: "owner@example.com",
	}).Error)

	resolved, err := svc.ResolveUserIDByEmail("owner@example.com")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	require.Equal(t, userID, *resolved)

	_, err = svc.ResolveUserIDByEmail("missing@example.com")
	require.Error(t, err)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "validation",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	risk, err := svc.GetByID(riskID)
	require.NoError(t, err)
	_, err = svc.Update(UpdateRiskParams{
		Risk:                    risk,
		ReplaceOwnerAssignments: true,
		OwnerAssignments: []RiskOwnerAssignment{
			{OwnerKind: "user", OwnerRef: uuid.New().String(), IsPrimary: true},
			{OwnerKind: "role", OwnerRef: "risk-admin", IsPrimary: true},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "only one primary owner assignment")
}

func TestRiskServiceListAndAcceptedCreatePath(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	actorID := uuid.New()
	sspID := uuid.New()
	reviewDeadline := time.Now().UTC().Add(7 * 24 * time.Hour)
	acceptanceJustification := "accepted pending mitigation"

	_, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:                   "Accepted risk",
			Description:             "accepted",
			Status:                  string(RiskStatusRiskAccepted),
			SSPID:                   sspID,
			SourceType:              string(RiskSourceTypeManual),
			ReviewDeadline:          &reviewDeadline,
			AcceptanceJustification: &acceptanceJustification,
			FirstSeenAt:             time.Now().UTC(),
			LastSeenAt:              time.Now().UTC(),
		},
		ActorUserID: &actorID,
	})
	require.NoError(t, err)

	_, err = svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "Open risk",
			Description: "open",
			Status:      string(RiskStatusOpen),
			SSPID:       sspID,
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		},
		ActorUserID: &actorID,
	})
	require.NoError(t, err)

	status := string(RiskStatusRiskAccepted)
	items, total, err := svc.List(ListParams{
		Filters:   ListFilters{Status: &status, SSPID: &sspID},
		SortField: "createdAt",
		SortOrder: "desc",
		Limit:     10,
		Offset:    0,
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, items, 1)
	require.Equal(t, status, items[0].Status)

	var acceptedEventCount int64
	require.NoError(t, db.Model(&RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", *items[0].ID, string(RiskEventTypeAccepted)).
		Count(&acceptedEventCount).Error)
	require.Equal(t, int64(1), acceptedEventCount)

	_, err = svc.Update(UpdateRiskParams{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "risk is required")
}

func TestRiskAuditHooksAreAppendOnly(t *testing.T) {
	event := &RiskEvent{}
	require.ErrorContains(t, event.BeforeUpdate(nil), "append-only")
	require.ErrorContains(t, event.BeforeDelete(nil), "append-only")

	review := &RiskReview{}
	require.ErrorContains(t, review.BeforeUpdate(nil), "append-only")
	require.ErrorContains(t, review.BeforeDelete(nil), "append-only")
}

func TestRiskServiceRejectsInvalidOwnerAssignments(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	base := Risk{
		Title:       "owner validation",
		Description: "owner validation",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}

	_, err := svc.Create(CreateRiskParams{
		Risk:             base,
		OwnerAssignments: []RiskOwnerAssignment{{OwnerKind: "team", OwnerRef: "ops", IsPrimary: true}},
	})
	require.ErrorContains(t, err, "invalid ownerKind")

	_, err = svc.Create(CreateRiskParams{
		Risk:             base,
		OwnerAssignments: []RiskOwnerAssignment{{OwnerKind: "user", OwnerRef: "not-a-uuid", IsPrimary: true}},
	})
	require.ErrorContains(t, err, "ownerRef must be a valid UUID")
}

func TestRiskServiceDeleteEvidenceLinkDeletesLegacyRowIDs(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "legacy-evidence-link",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	evidenceID := uuid.New()
	evidenceStreamID := uuid.New()
	require.NoError(t, db.Create(&testEvidenceRow{ID: evidenceID, UUID: evidenceStreamID, End: time.Now().UTC()}).Error)

	// Simulate migration overlap where both legacy and stream IDs may be linked.
	require.NoError(t, db.Create(&RiskEvidenceLink{RiskID: riskID, EvidenceID: evidenceID}).Error)
	require.NoError(t, db.Create(&RiskEvidenceLink{RiskID: riskID, EvidenceID: evidenceStreamID}).Error)

	actorID := uuid.New()
	deleted, err := svc.DeleteEvidenceLink(riskID, evidenceID, &actorID)
	require.NoError(t, err)
	require.True(t, deleted)

	var remaining int64
	require.NoError(t, db.Model(&RiskEvidenceLink{}).Where("risk_id = ?", riskID).Count(&remaining).Error)
	require.Zero(t, remaining)
}

func TestRiskServiceAddEvidenceLinkRejectsEvidenceWithoutStreamUUID(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "missing-stream-uuid",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	evidenceID := uuid.New()
	require.NoError(t, db.Create(&testEvidenceRow{ID: evidenceID, UUID: uuid.Nil, End: time.Now().UTC()}).Error)

	_, err := svc.AddEvidenceLink(riskID, evidenceID, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "missing stream uuid")
}

func TestRiskServiceAcceptRiskValidationAndSuccess(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "accept-risk",
		Description: "desc",
		Status:      string(RiskStatusInvestigating),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	actorID := uuid.New()

	_, err := svc.AcceptRisk(AcceptRiskParams{
		RiskID:         riskID,
		ActorUserID:    &actorID,
		Justification:  "   ",
		ReviewDeadline: time.Now().Add(24 * time.Hour),
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	_, err = svc.AcceptRisk(AcceptRiskParams{
		RiskID:         riskID,
		ActorUserID:    &actorID,
		Justification:  "accepted",
		ReviewDeadline: time.Now().Add(-24 * time.Hour),
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	deadline := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
	accepted, err := svc.AcceptRisk(AcceptRiskParams{
		RiskID:         riskID,
		ActorUserID:    &actorID,
		Justification:  "accepted until controls are in place",
		ReviewDeadline: deadline,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusRiskAccepted), accepted.Status)
	require.NotNil(t, accepted.ReviewDeadline)
	require.WithinDuration(t, deadline, *accepted.ReviewDeadline, time.Second)
	require.NotNil(t, accepted.LastReviewedAt)
	require.NotNil(t, accepted.AcceptanceJustification)
	require.Equal(t, "accepted until controls are in place", *accepted.AcceptanceJustification)

	_, err = svc.AcceptRisk(AcceptRiskParams{
		RiskID:         riskID,
		ActorUserID:    &actorID,
		Justification:  "cannot accept twice",
		ReviewDeadline: time.Now().Add(24 * time.Hour),
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.EqualError(t, err, "only risks in status investigating can be accepted")

	var reviewCount int64
	require.NoError(t, db.Model(&RiskReview{}).Where("risk_id = ?", riskID).Count(&reviewCount).Error)
	require.Equal(t, int64(0), reviewCount)

	var acceptedEventCount int64
	require.NoError(t, db.Model(&RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", riskID, string(RiskEventTypeAccepted)).
		Count(&acceptedEventCount).Error)
	require.Equal(t, int64(1), acceptedEventCount)

	var statusChangeEventCount int64
	require.NoError(t, db.Model(&RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", riskID, string(RiskEventTypeStatusChange)).
		Count(&statusChangeEventCount).Error)
	require.Equal(t, int64(1), statusChangeEventCount)
}

func TestRiskServiceReviewRiskDecisions(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	reviewDeadline := time.Now().Add(7 * 24 * time.Hour).UTC()
	acceptanceJustification := "accepted for now"
	require.NoError(t, db.Create(&Risk{
		UUIDModel:               relational.UUIDModel{ID: &riskID},
		Title:                   "review-risk",
		Description:             "desc",
		Status:                  string(RiskStatusRiskAccepted),
		SSPID:                   uuid.New(),
		SourceType:              string(RiskSourceTypeManual),
		ReviewDeadline:          &reviewDeadline,
		AcceptanceJustification: &acceptanceJustification,
		FirstSeenAt:             time.Now().UTC(),
		LastSeenAt:              time.Now().UTC(),
	}).Error)

	actorID := uuid.New()

	_, err := svc.ReviewRisk(ReviewRiskParams{
		RiskID:      riskID,
		ActorUserID: &actorID,
		Decision:    NormalizeRiskReviewDecision("invalid"),
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	_, err = svc.ReviewRisk(ReviewRiskParams{
		RiskID:      riskID,
		ActorUserID: &actorID,
		Decision:    RiskReviewDecisionExtend,
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	extraneousDeadline := time.Now().Add(24 * time.Hour).UTC()
	_, err = svc.ReviewRisk(ReviewRiskParams{
		RiskID:             riskID,
		ActorUserID:        &actorID,
		Decision:           RiskReviewDecisionReopen,
		NextReviewDeadline: &extraneousDeadline,
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.EqualError(t, err, "nextReviewDeadline must not be provided when decision is reopen")

	reviewedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	nextDeadline := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	notes := "extended after review"
	extended, err := svc.ReviewRisk(ReviewRiskParams{
		RiskID:             riskID,
		ActorUserID:        &actorID,
		ReviewedAt:         &reviewedAt,
		Decision:           RiskReviewDecisionExtend,
		Notes:              &notes,
		NextReviewDeadline: &nextDeadline,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusRiskAccepted), extended.Status)
	require.NotNil(t, extended.ReviewDeadline)
	require.WithinDuration(t, nextDeadline, *extended.ReviewDeadline, time.Second)
	require.NotNil(t, extended.LastReviewedAt)
	require.WithinDuration(t, reviewedAt, *extended.LastReviewedAt, time.Second)

	reopened, err := svc.ReviewRisk(ReviewRiskParams{
		RiskID:      riskID,
		ActorUserID: &actorID,
		Decision:    RiskReviewDecisionReopen,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusInvestigating), reopened.Status)
	require.Nil(t, reopened.ReviewDeadline)
	require.Nil(t, reopened.AcceptanceJustification)
	require.NotNil(t, reopened.LastReviewedAt)

	reviewAfterReopenDeadline := time.Now().Add(7 * 24 * time.Hour).UTC()
	_, err = svc.ReviewRisk(ReviewRiskParams{
		RiskID:             riskID,
		ActorUserID:        &actorID,
		Decision:           RiskReviewDecisionExtend,
		NextReviewDeadline: &reviewAfterReopenDeadline,
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.EqualError(t, err, "only risks in status risk-accepted can be reviewed")

	var reviews []RiskReview
	require.NoError(t, db.Where("risk_id = ?", riskID).Order("created_at asc").Find(&reviews).Error)
	require.Len(t, reviews, 2)
	require.Equal(t, "extend", reviews[0].Decision)
	require.Equal(t, "reopen", reviews[1].Decision)
	require.NotNil(t, reviews[0].ReviewJustification)
	require.Equal(t, notes, *reviews[0].ReviewJustification)

	var reviewedEventCount int64
	require.NoError(t, db.Model(&RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", riskID, string(RiskEventTypeReviewed)).
		Count(&reviewedEventCount).Error)
	require.Equal(t, int64(2), reviewedEventCount)

	var statusChangeEventCount int64
	require.NoError(t, db.Model(&RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", riskID, string(RiskEventTypeStatusChange)).
		Count(&statusChangeEventCount).Error)
	require.Equal(t, int64(1), statusChangeEventCount)
}

func TestRiskServiceReviewRiskReassess(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	actorID := uuid.New()
	low := "low"
	critical := "critical"
	medium := "medium"

	createRisk := func(status RiskStatus) uuid.UUID {
		riskID := uuid.New()
		require.NoError(t, db.Create(&Risk{
			UUIDModel:   relational.UUIDModel{ID: &riskID},
			Title:       "reassess-risk-" + string(status),
			Description: "desc",
			Status:      string(status),
			SSPID:       uuid.New(),
			SourceType:  string(RiskSourceTypeManual),
			Likelihood:  &low,
			Impact:      &low,
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		}).Error)
		return riskID
	}

	openRiskID := createRisk(RiskStatusOpen)
	nextDeadline := time.Now().Add(7 * 24 * time.Hour).UTC()

	_, err := svc.ReviewRisk(ReviewRiskParams{
		RiskID:      openRiskID,
		ActorUserID: &actorID,
		Decision:    RiskReviewDecisionReassess,
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.EqualError(t, err, "likelihood is required and must be one of: negligible, low, moderate, high, critical")

	_, err = svc.ReviewRisk(ReviewRiskParams{
		RiskID:             openRiskID,
		ActorUserID:        &actorID,
		Decision:           RiskReviewDecisionReassess,
		Likelihood:         &medium,
		Impact:             &critical,
		NextReviewDeadline: &nextDeadline,
	})
	require.Error(t, err)
	require.True(t, IsValidationError(err))
	require.EqualError(t, err, "nextReviewDeadline must not be provided when decision is reassess")

	notes := "risk score changed after reassessment"
	reassessed, err := svc.ReviewRisk(ReviewRiskParams{
		RiskID:      openRiskID,
		ActorUserID: &actorID,
		Decision:    RiskReviewDecisionReassess,
		Likelihood:  &medium,
		Impact:      &critical,
		Notes:       &notes,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusOpen), reassessed.Status)
	require.NotNil(t, reassessed.Likelihood)
	require.NotNil(t, reassessed.Impact)
	require.Equal(t, string(RiskLevelModerate), *reassessed.Likelihood)
	require.Equal(t, string(RiskLevelCritical), *reassessed.Impact)
	require.NotNil(t, reassessed.LastReviewedAt)

	var reviews []RiskReview
	require.NoError(t, db.Where("risk_id = ?", openRiskID).Order("created_at asc").Find(&reviews).Error)
	require.Len(t, reviews, 1)
	require.Equal(t, string(RiskReviewDecisionReassess), reviews[0].Decision)
	require.NotNil(t, reviews[0].ReassessedLikelihood)
	require.NotNil(t, reviews[0].ReassessedImpact)
	require.Equal(t, string(RiskLevelModerate), *reviews[0].ReassessedLikelihood)
	require.Equal(t, string(RiskLevelCritical), *reviews[0].ReassessedImpact)
	require.NotNil(t, reviews[0].ReviewJustification)
	require.Equal(t, notes, *reviews[0].ReviewJustification)

	var reassessEvents []RiskEvent
	require.NoError(t, db.Where("risk_id = ? AND event_type = ?", openRiskID, string(RiskEventTypeScoreReassessed)).Find(&reassessEvents).Error)
	require.Len(t, reassessEvents, 1)
	require.NotNil(t, reassessEvents[0].Details)
	require.NotEmpty(t, *reassessEvents[0].Details)
	require.Equal(t, string(RiskReviewDecisionReassess), reassessEvents[0].Payload["decision"])
	require.Equal(t, string(RiskStatusOpen), reassessEvents[0].Payload["status"])
	require.Equal(t, string(RiskLevelLow), reassessEvents[0].Payload["fromLikelihood"])
	require.Equal(t, string(RiskLevelLow), reassessEvents[0].Payload["fromImpact"])
	require.Equal(t, string(RiskLevelModerate), reassessEvents[0].Payload["toLikelihood"])
	require.Equal(t, string(RiskLevelCritical), reassessEvents[0].Payload["toImpact"])

	var reviewedEventCount int64
	require.NoError(t, db.Model(&RiskEvent{}).
		Where("risk_id = ? AND event_type = ?", openRiskID, string(RiskEventTypeReviewed)).
		Count(&reviewedEventCount).Error)
	require.Equal(t, int64(0), reviewedEventCount)

	for _, status := range []RiskStatus{RiskStatusInvestigating, RiskStatusMitigatingImplemented} {
		riskID := createRisk(status)
		_, err := svc.ReviewRisk(ReviewRiskParams{
			RiskID:      riskID,
			ActorUserID: &actorID,
			Decision:    RiskReviewDecisionReassess,
			Likelihood:  &medium,
			Impact:      &critical,
		})
		require.NoError(t, err)
	}

	for _, status := range []RiskStatus{RiskStatusRiskAccepted, RiskStatusMitigatingPlanned, RiskStatusClosed} {
		riskID := createRisk(status)
		_, err := svc.ReviewRisk(ReviewRiskParams{
			RiskID:      riskID,
			ActorUserID: &actorID,
			Decision:    RiskReviewDecisionReassess,
			Likelihood:  &medium,
			Impact:      &critical,
		})
		require.Error(t, err)
		require.True(t, IsValidationError(err))
		require.EqualError(t, err, "reassess is only allowed for risks in status open, investigating, or mitigating-implemented")
	}
}

func TestRiskServiceThreatAndRemediationCRUD(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "risk with threat/remediation",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	actorID := uuid.New()
	threat, err := svc.AddThreatRef(riskID, RiskThreatRefInput{
		System:     "CWE",
		ExternalID: "79",
		Title:      "Cross-site scripting",
	}, &actorID)
	require.NoError(t, err)
	require.NotNil(t, threat.ID)

	sameThreat, err := svc.AddThreatRef(riskID, RiskThreatRefInput{
		System:     "CWE",
		ExternalID: "79",
		Title:      "Cross-site scripting",
	}, &actorID)
	require.NoError(t, err)
	require.Equal(t, *threat.ID, *sameThreat.ID)

	loadedThreat, err := svc.GetThreatRef(riskID, *threat.ID)
	require.NoError(t, err)
	require.Equal(t, "CWE", loadedThreat.System)

	updatedThreat, err := svc.UpdateThreatRef(riskID, *threat.ID, RiskThreatRefInput{
		System:     "CWE",
		ExternalID: "79",
		Title:      "XSS updated",
	}, &actorID)
	require.NoError(t, err)
	require.Equal(t, "XSS updated", updatedThreat.Title)

	secondThreat, err := svc.AddThreatRef(riskID, RiskThreatRefInput{
		System:     "CWE",
		ExternalID: "89",
		Title:      "SQL injection",
	}, &actorID)
	require.NoError(t, err)
	require.NotNil(t, secondThreat.ID)

	_, err = svc.UpdateThreatRef(riskID, *secondThreat.ID, RiskThreatRefInput{
		System:     "CWE",
		ExternalID: "79",
		Title:      "Duplicate pair",
	}, &actorID)
	require.Error(t, err)
	require.True(t, IsValidationError(err))

	threatRows, total, err := svc.ListThreatRefs(riskID, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Len(t, threatRows, 2)

	desc := "Apply mitigations"
	remediation, err := svc.CreateRemediationTemplate(riskID, &RiskRemediationTemplateInput{
		Title:       "Fix risk",
		Description: &desc,
		Tasks: []RiskRemediationTaskInput{
			{Title: "Task A", OrderIndex: 1},
		},
	}, &actorID)
	require.NoError(t, err)
	require.NotNil(t, remediation.ID)
	require.Len(t, remediation.Tasks, 1)

	_, err = svc.CreateRemediationTemplate(riskID, &RiskRemediationTemplateInput{Title: "Duplicate"}, &actorID)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRemediationTemplateAlreadyExists)

	remediation, err = svc.UpsertRemediationTemplate(riskID, &RiskRemediationTemplateInput{
		Title: "Fix risk updated",
		Tasks: []RiskRemediationTaskInput{
			{Title: "Task B", OrderIndex: 1},
			{Title: "Task C", OrderIndex: 2},
		},
	}, &actorID)
	require.NoError(t, err)
	require.Equal(t, "Fix risk updated", remediation.Title)
	require.Len(t, remediation.Tasks, 2)

	loadedRemediation, err := svc.GetRemediationTemplate(riskID)
	require.NoError(t, err)
	require.Equal(t, "Fix risk updated", loadedRemediation.Title)
	require.Len(t, loadedRemediation.Tasks, 2)

	deletedThreat, err := svc.DeleteThreatRef(riskID, *threat.ID, &actorID)
	require.NoError(t, err)
	require.True(t, deletedThreat)
	deletedThreat, err = svc.DeleteThreatRef(riskID, *secondThreat.ID, &actorID)
	require.NoError(t, err)
	require.True(t, deletedThreat)
	deletedThreat, err = svc.DeleteThreatRef(riskID, *threat.ID, &actorID)
	require.NoError(t, err)
	require.False(t, deletedThreat)

	deletedRemediation, err := svc.DeleteRemediationTemplate(riskID, &actorID)
	require.NoError(t, err)
	require.True(t, deletedRemediation)
	deletedRemediation, err = svc.DeleteRemediationTemplate(riskID, &actorID)
	require.NoError(t, err)
	require.False(t, deletedRemediation)
}

func TestRiskServiceCreateAndUpdateWithInlineThreatAndRemediation(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	actorID := uuid.New()
	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "inline associations",
			Description: "desc",
			Status:      string(RiskStatusOpen),
			SSPID:       uuid.New(),
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		},
		ThreatRefs: []RiskThreatRefInput{
			{System: "CWE", ExternalID: "200", Title: "Data exposure"},
		},
		Remediation: &RiskRemediationTemplateInput{
			Title: "Mitigate",
			Tasks: []RiskRemediationTaskInput{{Title: "Task", OrderIndex: 1}},
		},
		ActorUserID: &actorID,
	})
	require.NoError(t, err)
	require.NotNil(t, created.ID)
	require.Len(t, created.ThreatRefs, 1)
	require.NotNil(t, created.Remediation)
	require.Len(t, created.Remediation.Tasks, 1)

	createdCopy := *created
	updated, err := svc.Update(UpdateRiskParams{
		Risk:               &createdCopy,
		ActorUserID:        &actorID,
		OldStatus:          created.Status,
		ReplaceThreatRefs:  true,
		ThreatRefs:         []RiskThreatRefInput{},
		ReplaceRemediation: true,
		Remediation:        nil,
	})
	require.NoError(t, err)
	require.Len(t, updated.ThreatRefs, 0)
	require.Nil(t, updated.Remediation)
}

func newRiskServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&Risk{},
		&RiskEvent{},
		&RiskReview{},
		&RiskEvidenceLink{},
		&RiskControlLink{},
		&RiskComponentLink{},
		&RiskSubjectLink{},
		&RiskOwnerAssignment{},
		&RiskThreatRef{},
		&RiskRemediationTemplate{},
		&RiskRemediationTask{},
		&testUserRow{},
		&testEvidenceRow{},
		&testControlRow{},
		&testSystemComponentRow{},
		&testAssessmentSubjectRow{},
	))
	require.NoError(t, EnsureIndexes(db))

	return db
}

type testUserRow struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey"`
	Email     string         `gorm:"type:text;uniqueIndex"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (testUserRow) TableName() string { return "ccf_users" }

type testEvidenceRow struct {
	ID   uuid.UUID `gorm:"type:uuid;primaryKey"`
	UUID uuid.UUID `gorm:"type:uuid;index"`
	End  time.Time
}

func (testEvidenceRow) TableName() string { return "evidences" }

type testControlRow struct {
	CatalogID uuid.UUID `gorm:"column:catalog_id;type:uuid;primaryKey"`
	ID        string    `gorm:"column:id;type:text;primaryKey"`
}

func (testControlRow) TableName() string { return "controls" }

type testSystemComponentRow struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey"`
}

func (testSystemComponentRow) TableName() string { return "system_components" }

type testAssessmentSubjectRow struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey"`
}

func (testAssessmentSubjectRow) TableName() string { return "assessment_subjects" }
