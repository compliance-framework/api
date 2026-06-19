package authz

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.User{}, &relational.SSOUserLink{}))
	return db
}

func newBuiltinForTest(t *testing.T, db *gorm.DB, cfg *config.Config) PDP {
	t.Helper()
	pdp, err := Open(DriverBuiltin, Options{DB: db, Config: cfg, Logger: zap.NewNop().Sugar()})
	require.NoError(t, err)
	return pdp
}

func createUser(t *testing.T, db *gorm.DB, email, authMethod string) *relational.User {
	t.Helper()
	u := &relational.User{Email: email, AuthMethod: authMethod}
	require.NoError(t, db.Create(u).Error)
	return u
}

func createLink(t *testing.T, db *gorm.DB, user *relational.User, provider string, groups []string) {
	t.Helper()
	link := &relational.SSOUserLink{
		UserID:     user.ID.String(),
		Provider:   provider,
		ExternalID: "ext-" + provider,
		Email:      user.Email,
		Groups:     sso.SerializeStringArray(groups),
		LastSync:   time.Now().Add(-time.Hour),
	}
	require.NoError(t, db.Create(link).Error)
}

func ssoConfig(provider string, requiredAdminGroups []string) *config.Config {
	return &config.Config{
		SSO: &config.SSOConfig{
			Enabled: true,
			Providers: map[string]config.SSOProviderConfig{
				provider: {Name: provider, RequiredAdminGroups: requiredAdminGroups},
			},
		},
	}
}

// TestBuiltin_DefaultResource covers the "authenticated = allowed" rule plus the
// public-access exception used by routes like agent ingest.
func TestBuiltin_DefaultResource(t *testing.T) {
	pdp := newBuiltinForTest(t, newTestDB(t), nil)
	ctx := context.Background()

	cases := []struct {
		name    string
		subject Subject
		reqCtx  map[string]any
		allow   bool
	}{
		{"authenticated user", Subject{Type: SubjectUser, ID: "u@example.com"}, nil, true},
		{"authenticated agent", Subject{Type: SubjectAgent, ID: "agent-1"}, nil, true},
		{"anonymous without public", Subject{Type: SubjectAnonymous}, nil, false},
		{"anonymous with public", Subject{Type: SubjectAnonymous}, map[string]any{ctxKeyAllowPublic: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := pdp.Evaluate(ctx, tc.subject, "create", Resource{Type: "evidence"}, tc.reqCtx)
			require.NoError(t, err)
			require.Equal(t, tc.allow, d.Allow, "reason: %s", d.Reason)
		})
	}
}

// TestBuiltin_Admin exercises every branch of the migrated RequireAdminGroups
// logic, asserting identical allow/deny outcomes.
func TestBuiltin_Admin(t *testing.T) {
	ctx := context.Background()
	adminResource := Resource{Type: ResourceAdmin}

	t.Run("user not found denies", func(t *testing.T) {
		pdp := newBuiltinForTest(t, newTestDB(t), ssoConfig("google", []string{"ccf-admins"}))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "ghost@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.False(t, d.Allow)
	})

	t.Run("non-sso user bypasses", func(t *testing.T) {
		db := newTestDB(t)
		createUser(t, db, "pw@example.com", "password")
		pdp := newBuiltinForTest(t, db, ssoConfig("google", []string{"ccf-admins"}))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "pw@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.True(t, d.Allow)
	})

	t.Run("sso disabled allows", func(t *testing.T) {
		db := newTestDB(t)
		createUser(t, db, "sso@example.com", "sso")
		pdp := newBuiltinForTest(t, db, &config.Config{SSO: nil})
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "sso@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.True(t, d.Allow)
	})

	t.Run("missing sso link denies", func(t *testing.T) {
		db := newTestDB(t)
		createUser(t, db, "sso@example.com", "sso")
		pdp := newBuiltinForTest(t, db, ssoConfig("google", []string{"ccf-admins"}))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "sso@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.False(t, d.Allow)
	})

	t.Run("unknown provider denies", func(t *testing.T) {
		db := newTestDB(t)
		u := createUser(t, db, "sso@example.com", "sso")
		createLink(t, db, u, "okta", []string{"ccf-admins"})
		pdp := newBuiltinForTest(t, db, ssoConfig("google", []string{"ccf-admins"}))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "sso@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.False(t, d.Allow)
	})

	t.Run("provider without required groups allows", func(t *testing.T) {
		db := newTestDB(t)
		u := createUser(t, db, "sso@example.com", "sso")
		createLink(t, db, u, "google", nil)
		pdp := newBuiltinForTest(t, db, ssoConfig("google", nil))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "sso@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.True(t, d.Allow)
	})

	t.Run("required group present allows", func(t *testing.T) {
		db := newTestDB(t)
		u := createUser(t, db, "sso@example.com", "sso")
		createLink(t, db, u, "google", []string{"ccf-admins", "other"})
		pdp := newBuiltinForTest(t, db, ssoConfig("google", []string{"ccf-admins"}))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "sso@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.True(t, d.Allow)
	})

	t.Run("required group missing denies", func(t *testing.T) {
		db := newTestDB(t)
		u := createUser(t, db, "sso@example.com", "sso")
		createLink(t, db, u, "google", []string{"other"})
		pdp := newBuiltinForTest(t, db, ssoConfig("google", []string{"ccf-admins"}))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "sso@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.False(t, d.Allow)
	})

	t.Run("group match is case insensitive", func(t *testing.T) {
		db := newTestDB(t)
		u := createUser(t, db, "sso@example.com", "sso")
		createLink(t, db, u, "google", []string{"CCF-Admins"})
		pdp := newBuiltinForTest(t, db, ssoConfig("google", []string{"ccf-admins"}))
		d, err := pdp.Evaluate(ctx, Subject{Type: SubjectUser, ID: "sso@example.com"}, "manage", adminResource, nil)
		require.NoError(t, err)
		require.True(t, d.Allow)
	})
}

func TestBuiltin_RequiresDB(t *testing.T) {
	_, err := Open(DriverBuiltin, Options{Logger: zap.NewNop().Sugar()})
	require.Error(t, err)
}

func TestBuiltin_Evaluations(t *testing.T) {
	pdp := newBuiltinForTest(t, newTestDB(t), nil)
	decisions, err := pdp.Evaluations(context.Background(), []EvalRequest{
		{Subject: Subject{Type: SubjectUser, ID: "u@example.com"}, Action: "create", Resource: Resource{Type: "evidence"}},
		{Subject: Subject{Type: SubjectAnonymous}, Action: "create", Resource: Resource{Type: "evidence"}},
	})
	require.NoError(t, err)
	require.Len(t, decisions, 2)
	require.True(t, decisions[0].Allow)
	require.False(t, decisions[1].Allow)
}
