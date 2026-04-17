package oscal

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGetControlIDsForAllProfilesFallsBackForProfilesMissingPivotRows(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`
		CREATE TABLE profile_controls (
			profile_id TEXT NOT NULL,
			control_catalog_id TEXT NOT NULL,
			control_id TEXT NOT NULL
		)
	`).Error)

	profileWithPivot := uuid.New()
	profileWithoutPivot := uuid.New()
	catalogID := uuid.New()
	require.NoError(t, db.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileWithPivot.String(),
		catalogID.String(),
		"ac-1",
	).Error)

	handler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
	handler.profileCache.Store(profileWithoutPivot, []string{"AC-1", "ac-2"})

	controlIDs, err := handler.getControlIDsForAllProfiles([]relational.Profile{
		{UUIDModel: relational.UUIDModel{ID: &profileWithPivot}},
		{UUIDModel: relational.UUIDModel{ID: &profileWithoutPivot}},
	})

	require.NoError(t, err)
	require.ElementsMatch(t, []string{"ac-1", "ac-2"}, controlIDs)
}

func TestNormalizeControlIDsDeduplicatesMixedCase(t *testing.T) {
	require.ElementsMatch(t, []string{"ac-1", "au-2"}, normalizeControlIDs([]string{"ac-1", "AC-1", "Au-2"}))
}

func TestBuildProfileSummariesRejectsNilProfileID(t *testing.T) {
	summaries, err := buildProfileSummaries([]relational.Profile{{}})

	require.Error(t, err)
	require.Nil(t, summaries)
}

func TestBuildProfileSummariesIncludesIDAndTitle(t *testing.T) {
	profileID := uuid.New()
	summaries, err := buildProfileSummaries([]relational.Profile{
		{
			UUIDModel: relational.UUIDModel{ID: &profileID},
			Metadata:  relational.Metadata{Title: "Profile A"},
		},
	})

	require.NoError(t, err)
	require.Equal(t, []profileSummary{{ID: profileID.String(), Title: "Profile A"}}, summaries)
}

func TestAttachProfileReturnsInternalServerErrorForUnexpectedSSPLoadError(t *testing.T) {
	handler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), closedSQLiteDB(t), nil, nil)
	sspID := uuid.New()
	profileID := uuid.New()
	ctx, rec := newSSPProfileRequestContext(http.MethodPut, sspID, profileID)

	require.NoError(t, handler.AttachProfile(ctx))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestAddProfileReturnsInternalServerErrorForUnexpectedSSPLoadError(t *testing.T) {
	handler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), closedSQLiteDB(t), nil, nil)
	sspID := uuid.New()
	profileID := uuid.New()
	ctx, rec := newSSPProfileRequestContext(http.MethodPost, sspID, profileID)

	require.NoError(t, handler.AddProfile(ctx))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestAddProfileReturnsInternalServerErrorForUnexpectedProfileLoadError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE system_security_plans (id TEXT PRIMARY KEY)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE control_implementations (id TEXT PRIMARY KEY, system_security_plan_id TEXT)`).Error)

	sspID := uuid.New()
	profileID := uuid.New()
	require.NoError(t, db.Exec("INSERT INTO system_security_plans (id) VALUES (?)", sspID.String()).Error)

	handler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
	ctx, rec := newSSPProfileRequestContext(http.MethodPost, sspID, profileID)

	require.NoError(t, handler.AddProfile(ctx))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestAddProfileDuplicateBindingSkipsControlResolution(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE system_security_plans (id TEXT PRIMARY KEY)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE profiles (id TEXT PRIMARY KEY)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE control_implementations (id TEXT PRIMARY KEY, system_security_plan_id TEXT)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE ssp_profiles (
		system_security_plan_id TEXT NOT NULL,
		profile_id TEXT NOT NULL,
		PRIMARY KEY (system_security_plan_id, profile_id)
	)`).Error)

	sspID := uuid.New()
	profileID := uuid.New()
	require.NoError(t, db.Exec("INSERT INTO system_security_plans (id) VALUES (?)", sspID.String()).Error)
	require.NoError(t, db.Exec("INSERT INTO profiles (id) VALUES (?)", profileID.String()).Error)
	require.NoError(t, db.Exec(
		"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
		sspID.String(),
		profileID.String(),
	).Error)

	handler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
	ctx, rec := newSSPProfileRequestContext(http.MethodPost, sspID, profileID)

	require.NoError(t, handler.AddProfile(ctx))
	require.Equal(t, http.StatusConflict, rec.Code)
}

func closedSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	return db
}

func newSSPProfileRequestContext(method string, sspID, profileID uuid.UUID) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	body := bytes.NewBufferString(`{"profileId":"` + profileID.String() + `"}`)
	req := httptest.NewRequest(method, "/", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(sspID.String())
	return ctx, rec
}
