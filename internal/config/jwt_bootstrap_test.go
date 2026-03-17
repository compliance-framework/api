package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrapJWTKeyPair_GenerateAndNoop(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "private.pem")
	publicKeyPath := filepath.Join(t.TempDir(), "public.pem")

	action, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, minimumJWTKeyBitSize, false)
	require.NoError(t, err)
	assert.Equal(t, JWTKeyBootstrapGenerated, action)

	_, err = loadRSAPrivateKey(privateKeyPath)
	require.NoError(t, err)
	_, err = loadRSAPublicKey(publicKeyPath)
	require.NoError(t, err)

	action, err = BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, minimumJWTKeyBitSize, false)
	require.NoError(t, err)
	assert.Equal(t, JWTKeyBootstrapNoop, action)
}

func TestBootstrapJWTKeyPair_DerivePublicFromExistingPrivate(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "private.pem")
	publicKeyPath := filepath.Join(filepath.Dir(privateKeyPath), "public.pem")

	_, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, minimumJWTKeyBitSize, false)
	require.NoError(t, err)

	require.NoError(t, os.Remove(publicKeyPath))

	action, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, minimumJWTKeyBitSize, false)
	require.NoError(t, err)
	assert.Equal(t, JWTKeyBootstrapDerivedPublic, action)

	_, err = loadRSAPublicKey(publicKeyPath)
	require.NoError(t, err)
}

func TestBootstrapJWTKeyPair_RegenerateWhenOnlyPublicExists(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "private.pem")
	publicKeyPath := filepath.Join(filepath.Dir(privateKeyPath), "public.pem")

	_, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, minimumJWTKeyBitSize, false)
	require.NoError(t, err)

	require.NoError(t, os.Remove(privateKeyPath))

	action, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, minimumJWTKeyBitSize, false)
	require.NoError(t, err)
	assert.Equal(t, JWTKeyBootstrapRegenerated, action)

	_, err = loadRSAPrivateKey(privateKeyPath)
	require.NoError(t, err)
	_, err = loadRSAPublicKey(publicKeyPath)
	require.NoError(t, err)
}

func TestBootstrapJWTKeyPair_RejectsSmallKeySizes(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "private.pem")
	publicKeyPath := filepath.Join(filepath.Dir(privateKeyPath), "public.pem")

	action, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, 1024, false)
	require.Error(t, err)
	assert.Empty(t, action)
	assert.Contains(t, err.Error(), "bit size must be at least")
}

func TestBootstrapJWTKeyPair_RejectsSamePath(t *testing.T) {
	samePath := filepath.Join(t.TempDir(), "jwt.pem")

	action, err := BootstrapJWTKeyPair(samePath, samePath, minimumJWTKeyBitSize, false)
	require.Error(t, err)
	assert.Empty(t, action)
	assert.Contains(t, err.Error(), "must be different")
}

func TestBootstrapJWTKeyPair_RejectsMismatchedExistingPair(t *testing.T) {
	privateOne := filepath.Join(t.TempDir(), "private1.pem")
	publicOne := filepath.Join(filepath.Dir(privateOne), "public1.pem")
	_, err := BootstrapJWTKeyPair(privateOne, publicOne, minimumJWTKeyBitSize, false)
	require.NoError(t, err)

	privateTwo := filepath.Join(filepath.Dir(privateOne), "private2.pem")
	publicTwo := filepath.Join(filepath.Dir(privateOne), "public2.pem")
	_, err = BootstrapJWTKeyPair(privateTwo, publicTwo, minimumJWTKeyBitSize, false)
	require.NoError(t, err)

	mismatchedPrivatePath := filepath.Join(filepath.Dir(privateOne), "mismatched_private.pem")
	mismatchedPublicPath := filepath.Join(filepath.Dir(privateOne), "mismatched_public.pem")
	privateData, err := os.ReadFile(privateOne)
	require.NoError(t, err)
	publicData, err := os.ReadFile(publicTwo)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mismatchedPrivatePath, privateData, 0o600))
	require.NoError(t, os.WriteFile(mismatchedPublicPath, publicData, 0o644))

	action, err := BootstrapJWTKeyPair(mismatchedPrivatePath, mismatchedPublicPath, minimumJWTKeyBitSize, false)
	require.Error(t, err)
	assert.Empty(t, action)
	assert.Contains(t, err.Error(), "invalid or mismatched")
}
