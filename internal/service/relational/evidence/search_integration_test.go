//go:build integration

package evidence

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/datatypes"
)

type EvidenceServiceSearchIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestEvidenceServiceSearchIntegration(t *testing.T) {
	suite.Run(t, new(EvidenceServiceSearchIntegrationSuite))
}

func (suite *EvidenceServiceSearchIntegrationSuite) TestSearchPaginatedSortsLatestStreamsAndFiltersByName() {
	suite.Require().NoError(suite.Migrator.Refresh())

	now := time.Now().UTC()
	stream := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	evidences := []relational.Evidence{
		{
			UUID:  stream,
			Title: "Zeta Evidence",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			Title: "Alpha Evidence",
			Start: now.Add(-3 * time.Minute),
			End:   now.Add(-2 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "not-satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			Title: "Beta Evidence",
			Start: now.Add(-4 * time.Minute),
			End:   now.Add(-3 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "GCP"},
			},
		},
		{
			UUID:  stream,
			Title: "Old Zeta Evidence",
			Start: now.Add(-11 * time.Minute),
			End:   now.Add(-10 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "not-satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	svc := NewEvidenceService(suite.DB, nil, nil, nil)
	filter := labelfilter.Filter{}

	results, total, err := svc.SearchPaginated(filter, SearchOptions{Limit: 10})
	suite.Require().NoError(err)
	suite.Equal(int64(3), total)
	suite.Equal([]string{"Zeta Evidence", "Alpha Evidence", "Beta Evidence"}, relationalEvidenceTitles(results))

	results, total, err = svc.SearchPaginated(filter, SearchOptions{
		Limit:         10,
		SortBy:        SearchSortByLastSeenAt,
		SortDirection: SearchSortDirectionAsc,
	})
	suite.Require().NoError(err)
	suite.Equal(int64(3), total)
	suite.Equal([]string{"Beta Evidence", "Alpha Evidence", "Zeta Evidence"}, relationalEvidenceTitles(results))

	results, total, err = svc.SearchPaginated(filter, SearchOptions{
		Limit:         10,
		SortBy:        SearchSortByName,
		SortDirection: SearchSortDirectionAsc,
	})
	suite.Require().NoError(err)
	suite.Equal(int64(3), total)
	suite.Equal([]string{"Alpha Evidence", "Beta Evidence", "Zeta Evidence"}, relationalEvidenceTitles(results))

	results, total, err = svc.SearchPaginated(filter, SearchOptions{
		Limit:         10,
		SortBy:        SearchSortByStatus,
		SortDirection: SearchSortDirectionAsc,
	})
	suite.Require().NoError(err)
	suite.Equal(int64(3), total)
	suite.Equal([]string{"Alpha Evidence", "Beta Evidence", "Zeta Evidence"}, relationalEvidenceTitles(results))

	results, total, err = svc.SearchPaginated(filter, SearchOptions{
		Limit: 10,
		Name:  "alpha",
	})
	suite.Require().NoError(err)
	suite.Equal(int64(1), total)
	suite.Equal([]string{"Alpha Evidence"}, relationalEvidenceTitles(results))
}

func (suite *EvidenceServiceSearchIntegrationSuite) TestSearchPaginatedCombinesLabelAndNameFilters() {
	suite.Require().NoError(suite.Migrator.Refresh())

	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  uuid.New(),
			Title: "AWS Evidence",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.New(),
			Title: "AWS Evidence",
			Start: now.Add(-3 * time.Minute),
			End:   now.Add(-2 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "GCP"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	svc := NewEvidenceService(suite.DB, nil, nil, nil)
	results, total, err := svc.SearchPaginated(labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Condition: &labelfilter.Condition{
				Label:    "provider",
				Operator: "=",
				Value:    "aws",
			},
		},
	}, SearchOptions{
		Limit: 10,
		Name:  "aws",
	})

	suite.Require().NoError(err)
	suite.Equal(int64(1), total)
	suite.Equal([]string{"AWS Evidence"}, relationalEvidenceTitles(results))
	suite.Equal("AWS", results[0].Labels[0].Value)
}

func (suite *EvidenceServiceSearchIntegrationSuite) TestSearchPaginatedTreatsNameLikeMetacharactersLiterally() {
	suite.Require().NoError(suite.Migrator.Refresh())

	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  uuid.New(),
			Title: "CPU 100% Evidence",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
		},
		{
			UUID:  uuid.New(),
			Title: "CPU 100x Evidence",
			Start: now.Add(-3 * time.Minute),
			End:   now.Add(-2 * time.Minute),
		},
		{
			UUID:  uuid.New(),
			Title: "Disk io_await Evidence",
			Start: now.Add(-4 * time.Minute),
			End:   now.Add(-3 * time.Minute),
		},
		{
			UUID:  uuid.New(),
			Title: "Disk ioXawait Evidence",
			Start: now.Add(-5 * time.Minute),
			End:   now.Add(-4 * time.Minute),
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	svc := NewEvidenceService(suite.DB, nil, nil, nil)

	results, total, err := svc.SearchPaginated(labelfilter.Filter{}, SearchOptions{
		Limit: 10,
		Name:  "100%",
	})
	suite.Require().NoError(err)
	suite.Equal(int64(1), total)
	suite.Equal([]string{"CPU 100% Evidence"}, relationalEvidenceTitles(results))

	results, total, err = svc.SearchPaginated(labelfilter.Filter{}, SearchOptions{
		Limit: 10,
		Name:  "io_await",
	})
	suite.Require().NoError(err)
	suite.Equal(int64(1), total)
	suite.Equal([]string{"Disk io_await Evidence"}, relationalEvidenceTitles(results))
}

func (suite *EvidenceServiceSearchIntegrationSuite) TestStatusCountsReturnEmptySlicesWhenNoRowsMatch() {
	suite.Require().NoError(suite.Migrator.Refresh())

	svc := NewEvidenceService(suite.DB, nil, nil, nil)

	rows, err := svc.GetStatusCountsAtPoint(labelfilter.Filter{}, nil)
	suite.Require().NoError(err)
	suite.NotNil(rows)
	suite.Empty(rows)

	rows, err = svc.GetStatusCountsByUUIDAtPoint(uuid.New(), nil)
	suite.Require().NoError(err)
	suite.NotNil(rows)
	suite.Empty(rows)

	rows, err = svc.GetStatusCountsByFilters(labelfilter.Filter{})
	suite.Require().NoError(err)
	suite.NotNil(rows)
	suite.Empty(rows)
}

func (suite *EvidenceServiceSearchIntegrationSuite) TestStatusCountsByFiltersDedupesOverlappingEvidenceStreams() {
	suite.Require().NoError(suite.Migrator.Refresh())

	now := time.Now().UTC()
	evidence := relational.Evidence{
		UUID:  uuid.New(),
		Title: "overlapping evidence",
		Start: now.Add(-time.Minute),
		End:   now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
			State: "satisfied",
		}),
		Labels: []relational.Labels{
			{Name: "env", Value: "prod"},
			{Name: "tier", Value: "app"},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidence).Error)

	svc := NewEvidenceService(suite.DB, nil, nil, nil)
	rows, err := svc.GetStatusCountsByFilters(
		labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "env", Operator: "=", Value: "prod"}}},
		labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "tier", Operator: "=", Value: "app"}}},
	)
	suite.Require().NoError(err)
	suite.Require().Len(rows, 1)
	suite.Equal("satisfied", rows[0].Status)
	suite.Equal(int64(1), rows[0].Count)
}

func relationalEvidenceTitles(items []relational.Evidence) []string {
	titles := make([]string, 0, len(items))
	for _, item := range items {
		titles = append(titles, item.Title)
	}
	return titles
}
