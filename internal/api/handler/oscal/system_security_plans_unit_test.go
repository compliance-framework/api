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
	profileControlsCache.store(profileWithoutPivot, []string{"AC-1", "ac-2"})
	t.Cleanup(func() { profileControlsCache.invalidate(profileWithoutPivot) })

	controlIDs, err := handler.getControlIDsForAllProfiles([]relational.Profile{
		{UUIDModel: relational.UUIDModel{ID: &profileWithPivot}},
		{UUIDModel: relational.UUIDModel{ID: &profileWithoutPivot}},
	})

	require.NoError(t, err)
	require.ElementsMatch(t, []string{"ac-1", "ac-2"}, controlIDs)
}

func TestExtractControlIDsFromProfileDoesNotCacheEmptyResult(t *testing.T) {
	// Regression: a profile whose import has no include-controls resolves to zero
	// controls transiently. That empty result must NOT be cached, otherwise the
	// in-memory profileCache is poisoned for the process lifetime (it is never
	// invalidated when the profile's imports later change), causing attaches to
	// fail with "no controls were resolved from the selected profile".
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	handler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)

	profileID := uuid.New()
	// No imports -> resolves to zero controls without touching the DB.
	profile := relational.Profile{UUIDModel: relational.UUIDModel{ID: &profileID}}

	controlIDs, err := handler.extractControlIDsFromProfile(&profile)
	require.NoError(t, err)
	require.Empty(t, controlIDs)

	_, cached := profileControlsCache.load(profileID)
	require.False(t, cached, "empty resolution must not be cached")
}

func TestSyncProfileControlsInvalidatesCache(t *testing.T) {
	// Regression: when a profile's controls change, SyncProfileControls rewrites
	// the profile_controls pivot. It must also invalidate the in-memory cache,
	// otherwise getControlIDsForProfile keeps returning the stale cached set
	// instead of the freshly-resolved controls. The invalidation is deferred, so
	// it runs on every return path — including this early-error one (no schema).
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	profileID := uuid.New()
	profileControlsCache.store(profileID, []string{"stale-1", "stale-2"})
	t.Cleanup(func() { profileControlsCache.invalidate(profileID) })

	// Resolution fails (no profiles table), but the deferred invalidation must run.
	_, err = SyncProfileControls(db, profileID)
	require.Error(t, err)

	_, cached := profileControlsCache.load(profileID)
	require.False(t, cached, "SyncProfileControls must invalidate the cached entry")
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
