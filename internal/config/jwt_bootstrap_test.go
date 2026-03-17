package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapJWTKeyPair_GenerateAndNoop(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "private.pem")
	publicKeyPath := filepath.Join(t.TempDir(), "public.pem")

	action, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, 1024, false)
	if err != nil {
		t.Fatalf("expected bootstrap to generate keys, got error: %v", err)
	}
	if action != JWTKeyBootstrapGenerated {
		t.Fatalf("expected action %q, got %q", JWTKeyBootstrapGenerated, action)
	}

	if _, err := loadRSAPrivateKey(privateKeyPath); err != nil {
		t.Fatalf("expected generated private key to be readable, got error: %v", err)
	}
	if _, err := loadRSAPublicKey(publicKeyPath); err != nil {
		t.Fatalf("expected generated public key to be readable, got error: %v", err)
	}

	action, err = BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, 1024, false)
	if err != nil {
		t.Fatalf("expected bootstrap noop when both keys exist, got error: %v", err)
	}
	if action != JWTKeyBootstrapNoop {
		t.Fatalf("expected action %q, got %q", JWTKeyBootstrapNoop, action)
	}
}

func TestBootstrapJWTKeyPair_DerivePublicFromExistingPrivate(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "private.pem")
	publicKeyPath := filepath.Join(filepath.Dir(privateKeyPath), "public.pem")

	if _, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, 1024, false); err != nil {
		t.Fatalf("expected setup bootstrap to generate keys, got error: %v", err)
	}

	if err := os.Remove(publicKeyPath); err != nil {
		t.Fatalf("expected to remove public key for test setup, got error: %v", err)
	}

	action, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, 1024, false)
	if err != nil {
		t.Fatalf("expected bootstrap to derive missing public key, got error: %v", err)
	}
	if action != JWTKeyBootstrapDerivedPublic {
		t.Fatalf("expected action %q, got %q", JWTKeyBootstrapDerivedPublic, action)
	}

	if _, err := loadRSAPublicKey(publicKeyPath); err != nil {
		t.Fatalf("expected derived public key to be readable, got error: %v", err)
	}
}

func TestBootstrapJWTKeyPair_RegenerateWhenOnlyPublicExists(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "private.pem")
	publicKeyPath := filepath.Join(filepath.Dir(privateKeyPath), "public.pem")

	if _, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, 1024, false); err != nil {
		t.Fatalf("expected setup bootstrap to generate keys, got error: %v", err)
	}

	if err := os.Remove(privateKeyPath); err != nil {
		t.Fatalf("expected to remove private key for test setup, got error: %v", err)
	}

	action, err := BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, 1024, false)
	if err != nil {
		t.Fatalf("expected bootstrap to regenerate missing private key, got error: %v", err)
	}
	if action != JWTKeyBootstrapRegenerated {
		t.Fatalf("expected action %q, got %q", JWTKeyBootstrapRegenerated, action)
	}

	if _, err := loadRSAPrivateKey(privateKeyPath); err != nil {
		t.Fatalf("expected regenerated private key to be readable, got error: %v", err)
	}
	if _, err := loadRSAPublicKey(publicKeyPath); err != nil {
		t.Fatalf("expected regenerated public key to be readable, got error: %v", err)
	}
}
