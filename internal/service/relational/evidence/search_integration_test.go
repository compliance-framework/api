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

func relationalEvidenceTitles(items []relational.Evidence) []string {
	titles := make([]string, 0, len(items))
	for _, item := range items {
		titles = append(titles, item.Title)
	}
	return titles
}
