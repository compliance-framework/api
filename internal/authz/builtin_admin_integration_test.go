//go:build integration

package authz

import (
	"context"
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

// setupAuthzDB returns an in-memory SQLite DB migrated for the models the builtin admin
// path touches.
func setupAuthzDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.User{}, &relational.SSOUserLink{}))
	return db
}

func ssoEnabledConfig(requiredAdminGroups []string) *config.Config {
	return &config.Config{
		SSO: &config.SSOConfig{
			Enabled: true,
			Providers: map[string]config.SSOProviderConfig{
				"test": {Name: "test", RequiredAdminGroups: requiredAdminGroups},
			},
		},
	}
}

func createUser(t *testing.T, db *gorm.DB, email, authMethod string) relational.User {
	t.Helper()
	user := relational.User{Email: email, FirstName: "Test", LastName: "User", AuthMethod: authMethod}
	require.NoError(t, db.Create(&user).Error)
	return user
}

func createSSOLink(t *testing.T, db *gorm.DB, user relational.User, provider string, groups []string) {
	t.Helper()
	require.NoError(t, db.Create(&relational.SSOUserLink{
		UserID:     user.ID.String(),
		Provider:   provider,
		ExternalID: user.Email,
		Email:      user.Email,
		Groups:     sso.SerializeStringArray(groups),
		LastSync:   time.Now(),
	}).Error)
}

// evalAdmin runs the builtin admin decision for the given user email.
func evalAdmin(t *testing.T, db *gorm.DB, cfg *config.Config, email string) Decision {
	t.Helper()
	b := NewBuiltin(db, cfg, zap.NewNop().Sugar())
	dec, err := b.Evaluate(context.Background(),
		Subject{Type: "user", ID: email}, ActionManage, Resource{Type: ResourceAdmin}, nil)
	require.NoError(t, err)
	return dec
}

// TestBuiltinAdminGenuineDBErrorReturnsError locks in the single branch where the builtin
// returns a non-nil error (which the PEP maps to 500, NOT 403): a genuine DB failure
// loading the user. Forced by querying a DB where the users table was never migrated, so
// gorm returns "no such table" — which is not gorm.ErrRecordNotFound.
func TestBuiltinAdminGenuineDBErrorReturnsError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// Intentionally do NOT migrate relational.User.

	b := NewBuiltin(db, ssoEnabledConfig([]string{"ccf-admins"}), zap.NewNop().Sugar())
	dec, evalErr := b.Evaluate(context.Background(),
		Subject{Type: "user", ID: "sso@example.com"}, ActionManage, Resource{Type: ResourceAdmin}, nil)
	require.Error(t, evalErr, "a non-RecordNotFound DB failure must surface as an error (→500), not a deny")
	require.False(t, dec.Allow)
}

// TestBuiltinAdminDecisionMatrix locks in zero-behavior-change for the admin-group
// enforcement that moved out of the old RequireAdminGroups middleware. Each case mirrors
// a branch of the original logic.
func TestBuiltinAdminDecisionMatrix(t *testing.T) {
	t.Run("password user is super admin -> allow", func(t *testing.T) {
		db := setupAuthzDB(t)
		createUser(t, db, "pw@example.com", "password")
		require.True(t, evalAdmin(t, db, ssoEnabledConfig([]string{"ccf-admins"}), "pw@example.com").Allow)
	})

	t.Run("sso enforcement disabled -> allow", func(t *testing.T) {
		db := setupAuthzDB(t)
		createUser(t, db, "sso@example.com", "sso")
		cfg := &config.Config{SSO: &config.SSOConfig{Enabled: false}}
		require.True(t, evalAdmin(t, db, cfg, "sso@example.com").Allow)
	})

	t.Run("sso user, no required groups configured -> allow", func(t *testing.T) {
		db := setupAuthzDB(t)
		user := createUser(t, db, "sso@example.com", "sso")
		createSSOLink(t, db, user, "test", []string{"auditors"})
		require.True(t, evalAdmin(t, db, ssoEnabledConfig(nil), "sso@example.com").Allow)
	})

	t.Run("sso user with required group -> allow", func(t *testing.T) {
		db := setupAuthzDB(t)
		user := createUser(t, db, "sso@example.com", "sso")
		createSSOLink(t, db, user, "test", []string{"ccf-admins", "auditors"})
		require.True(t, evalAdmin(t, db, ssoEnabledConfig([]string{"ccf-admins"}), "sso@example.com").Allow)
	})

	t.Run("sso user missing required group -> deny", func(t *testing.T) {
		db := setupAuthzDB(t)
		user := createUser(t, db, "sso@example.com", "sso")
		createSSOLink(t, db, user, "test", []string{"auditors"})
		require.False(t, evalAdmin(t, db, ssoEnabledConfig([]string{"ccf-admins"}), "sso@example.com").Allow)
	})

	t.Run("sso user with no link -> deny", func(t *testing.T) {
		db := setupAuthzDB(t)
		createUser(t, db, "sso@example.com", "sso")
		require.False(t, evalAdmin(t, db, ssoEnabledConfig([]string{"ccf-admins"}), "sso@example.com").Allow)
	})

	t.Run("sso user, unknown provider -> deny", func(t *testing.T) {
		db := setupAuthzDB(t)
		user := createUser(t, db, "sso@example.com", "sso")
		createSSOLink(t, db, user, "unknown-provider", []string{"ccf-admins"})
		require.False(t, evalAdmin(t, db, ssoEnabledConfig([]string{"ccf-admins"}), "sso@example.com").Allow)
	})

	t.Run("unknown user -> deny", func(t *testing.T) {
		db := setupAuthzDB(t)
		require.False(t, evalAdmin(t, db, ssoEnabledConfig([]string{"ccf-admins"}), "ghost@example.com").Allow)
	})
}
