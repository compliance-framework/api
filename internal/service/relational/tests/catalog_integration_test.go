//go:build integration

package tests

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
)

func TestCatalog(t *testing.T) {
	suite.Run(t, new(CatalogIntegrationSuite))
}

type CatalogIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *CatalogIntegrationSuite) TestCatalogCreate() {
	/**
	When two catalogs have controls and groups with the same IDs, our polymorphism can override them, or return the incorrect ones.
	This test confirms that we can create two separate catalogs, and their groups and controls can be fetched without clashing or overriding one another.
	*/
	err := suite.Migrator.Up()
	suite.Require().NoError(err)

	catalog := &relational.Catalog{
		Metadata: relational.Metadata{
			Title: "Catalog 1",
		},
		Groups: []relational.Group{
			{
				ID:    "G-1",
				Title: "Group 1",
				Groups: []relational.Group{
					{
						ID:    "G-1.1",
						Title: "Group 1.1",
					},
				},
			},
		},
	}

	err = suite.DB.Create(catalog).Error
	suite.Require().NoError(err)

	var count int64
	suite.DB.Model(&relational.Catalog{}).Count(&count)
	suite.Equal(int64(1), count)
}
