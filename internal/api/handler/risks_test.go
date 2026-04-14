package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestParseScoreTimeseriesParamsRejectsExcessiveRange(t *testing.T) {
	e := echo.New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 0, maxRiskScoreRangeDays+1)
	req := httptest.NewRequest(http.MethodGet, "/risks/score-timeseries?from="+from.Format(time.RFC3339)+"&to="+to.Format(time.RFC3339), nil)
	ctx := e.NewContext(req, httptest.NewRecorder())

	_, _, _, _, err := parseScoreTimeseriesParams(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "score timeseries range must not exceed")
}

func TestMapRiskScoreToResponseRequiresID(t *testing.T) {
	_, err := mapRiskScoreToResponse(riskrel.RiskScore{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing required id")

	id := uuid.New()
	resp, err := mapRiskScoreToResponse(riskrel.RiskScore{
		UUIDModel: relational.UUIDModel{ID: &id},
		RiskID:    uuid.New(),
		SSPID:     uuid.New(),
	})
	require.NoError(t, err)
	require.Equal(t, id, resp.ID)
}
