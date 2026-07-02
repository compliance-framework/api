//go:build integration

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func TestLineagePerf(t *testing.T) {
	suite.Run(t, new(LineagePerfSuite))
}

type LineagePerfSuite struct {
	tests.IntegrationTestSuite
}

// callRoots invokes the Roots handler directly against the real DB and returns
// the status code + wall-clock duration, failing hard if it hangs.
func (suite *LineagePerfSuite) callRoots() (int, time.Duration) {
	code, dur, _ := suite.callRootsBody()
	return code, dur
}

func (suite *LineagePerfSuite) callRootsBody() (int, time.Duration, []byte) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/lineage/roots", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	h := NewLineageHandler(zap.NewNop().Sugar(), suite.DB)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- h.Roots(ctx) }()
	select {
	case err := <-done:
		suite.Require().NoError(err)
		return rec.Code, time.Since(start), rec.Body.Bytes()
	case <-time.After(90 * time.Second):
		suite.FailNow("Roots hung > 90s")
		return 0, 0, nil
	}
}

func (suite *LineagePerfSuite) TestRootsEmpty() {
	suite.Require().NoError(suite.Migrator.Refresh())
	code, dur := suite.callRoots()
	suite.Equal(http.StatusOK, code)
	suite.T().Logf("EMPTY roots: %s", dur)
}

func (suite *LineagePerfSuite) TestRootsWithCatalogAndEvidence() {
	suite.Require().NoError(suite.Migrator.Refresh())

	const (
		nControls = 150
		nEvidence = 5000
	)

	catID := uuid.New()
	now := time.Now().UTC()
	controls := make([]relational.Control, 0, nControls)
	for i := 0; i < nControls; i++ {
		controls = append(controls, relational.Control{
			CatalogID: catID,
			ID:        fmt.Sprintf("ac-%d", i),
			Title:     fmt.Sprintf("Control %d", i),
		})
	}
	catalog := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Big Standard", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Groups: []relational.Group{{
			CatalogID: catID,
			ID:        "grp",
			Title:     "Group",
			Controls:  controls,
		}},
	}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)

	// One filter per control (a label condition scope), attached via filter_controls.
	for i := 0; i < nControls; i++ {
		f := relational.Filter{
			Name: fmt.Sprintf("f-%d", i),
			Filter: datatypes.NewJSONType(labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{Label: "svc", Operator: "=", Value: "ec2"},
				},
			}),
		}
		suite.Require().NoError(suite.DB.Create(&f).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
			f.ID, catID, fmt.Sprintf("ac-%d", i),
		).Error)
	}

	// A label + a pile of latest-evidence streams that match it.
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('svc','ec2') ON CONFLICT DO NOTHING").Error)

	evidences := make([]relational.Evidence, 0, nEvidence)
	for i := 0; i < nEvidence; i++ {
		id := uuid.New()
		evidences = append(evidences, relational.Evidence{
			UUIDModel: relational.UUIDModel{ID: &id},
			UUID:      uuid.New(),
			Title:     "e",
			Start:     now,
			End:       now,
			Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
		})
	}
	suite.Require().NoError(suite.DB.CreateInBatches(&evidences, 500).Error)
	// Join every evidence row to the matching label.
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) SELECT id, 'svc', 'ec2' FROM evidences").Error)

	code, dur, body := suite.callRootsBody()
	suite.Equal(http.StatusOK, code)
	suite.T().Logf("POPULATED roots (%d controls, %d filters, %d evidence): %s", nControls, nControls, nEvidence, dur)

	// Correctness: every control has a filter matched by 5000 satisfied streams,
	// so the catalog root must roll up as fully satisfied.
	var resp struct {
		Data []struct {
			NodeType   string `json:"nodeType"`
			Compliance struct {
				TotalControls     int     `json:"totalControls"`
				Satisfied         int     `json:"satisfied"`
				NotSatisfied      int     `json:"notSatisfied"`
				CompliancePercent float64 `json:"compliancePercent"`
			} `json:"compliance"`
		} `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(body, &resp))
	suite.Require().Len(resp.Data, 1)
	root := resp.Data[0]
	suite.Equal("standard-catalog", root.NodeType)
	suite.Equal(nControls, root.Compliance.TotalControls, "all controls in scope")
	suite.Equal(nControls, root.Compliance.Satisfied, "every control satisfied")
	suite.Equal(0, root.Compliance.NotSatisfied)
	suite.InDelta(100.0, root.Compliance.CompliancePercent, 0.001)

	// Regression guard: this used to take ~29s (per-filter N+1); keep it well under.
	suite.Less(dur, 5*time.Second, "roots rollup must not regress into an N+1")
}
