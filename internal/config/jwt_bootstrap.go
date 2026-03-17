package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type JWTKeyBootstrapAction string

const (
	minimumJWTKeyBitSize                               = 2048
	JWTKeyBootstrapNoop          JWTKeyBootstrapAction = "noop"
	JWTKeyBootstrapGenerated     JWTKeyBootstrapAction = "generated"
	JWTKeyBootstrapDerivedPublic JWTKeyBootstrapAction = "derived_public"
	JWTKeyBootstrapRegenerated   JWTKeyBootstrapAction = "regenerated"
)

// BootstrapJWTKeyPair ensures a matching JWT RSA keypair exists at the given paths.
//
// Behavior:
//   - when both files exist and force=false: no-op
//   - when only private exists and force=false: derives and writes the public key
//   - otherwise: generates a new keypair and writes both files
func BootstrapJWTKeyPair(privateKeyPath, publicKeyPath string, bitSize int, force bool) (JWTKeyBootstrapAction, error) {
	privateKeyPath = normalizeKeyPath(privateKeyPath)
	publicKeyPath = normalizeKeyPath(publicKeyPath)

	if privateKeyPath == "" {
		return "", fmt.Errorf("private key path cannot be empty")
	}
	if publicKeyPath == "" {
		return "", fmt.Errorf("public key path cannot be empty")
	}
	if bitSize < minimumJWTKeyBitSize {
		return "", fmt.Errorf("bit size must be at least %d", minimumJWTKeyBitSize)
	}

	equal, err := keyPathsReferToSameLocation(privateKeyPath, publicKeyPath)
	if err != nil {
		return "", err
	}
	if equal {
		return "", fmt.Errorf("private and public key paths must be different")
	}

	privateExists, err := fileExists(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to check private key path %s: %w", privateKeyPath, err)
	}

	publicExists, err := fileExists(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to check public key path %s: %w", publicKeyPath, err)
	}

	if !force {
		if privateExists && publicExists {
			if err := validateExistingJWTKeyPair(privateKeyPath, publicKeyPath); err != nil {
				return "", fmt.Errorf("existing JWT keypair is invalid or mismatched: %w; rerun with --force to regenerate", err)
			}
			return JWTKeyBootstrapNoop, nil
		}

		if privateExists && !publicExists {
			privateKey, err := loadRSAPrivateKey(privateKeyPath)
			if err != nil {
				return "", fmt.Errorf("failed to load existing private key from %s: %w", privateKeyPath, err)
			}

			if err := writeRSAPublicKey(publicKeyPath, &privateKey.PublicKey); err != nil {
				return "", err
			}

			return JWTKeyBootstrapDerivedPublic, nil
		}
	}

	privateKey, publicKey, err := GenerateKeyPair(bitSize)
	if err != nil {
		return "", err
	}

	if err := writeRSAPrivateKey(privateKeyPath, privateKey); err != nil {
		return "", err
	}

	if err := writeRSAPublicKey(publicKeyPath, publicKey); err != nil {
		return "", err
	}

	if privateExists || publicExists {
		return JWTKeyBootstrapRegenerated, nil
	}

	return JWTKeyBootstrapGenerated, nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func writeRSAPrivateKey(path string, key *rsa.PrivateKey) error {
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return writePEMAtomically(path, privateKeyPEM, 0o600)
}

func writeRSAPublicKey(path string, key *rsa.PublicKey) error {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	return writePEMAtomically(path, publicKeyPEM, 0o644)
}

func ensureParentDirectory(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("unable to create parent directory %s: %w", dir, err)
	}

	return nil
}

func normalizeKeyPath(path string) string {
	path = stripQuotes(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func keyPathsReferToSameLocation(privateKeyPath, publicKeyPath string) (bool, error) {
	privateAbs, err := filepath.Abs(privateKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to resolve private key path %s: %w", privateKeyPath, err)
	}
	publicAbs, err := filepath.Abs(publicKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to resolve public key path %s: %w", publicKeyPath, err)
	}

	privateResolved := resolvePathIfExists(privateAbs)
	publicResolved := resolvePathIfExists(publicAbs)
	return privateResolved == publicResolved, nil
}

func resolvePathIfExists(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}
	return path
}

func validateExistingJWTKeyPair(privateKeyPath, publicKeyPath string) error {
	privateKey, err := loadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	publicKey, err := loadRSAPublicKey(publicKeyPath)
	if err != nil {
		return err
	}
	if !rsaPublicKeysEqual(&privateKey.PublicKey, publicKey) {
		return fmt.Errorf("public key does not match private key")
	}
	return nil
}

func rsaPublicKeysEqual(a, b *rsa.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.E == b.E && a.N.Cmp(b.N) == 0
}

func writePEMAtomically(path string, data []byte, mode os.FileMode) error {
	if err := ensureParentDirectory(path); err != nil {
		return err
	}
	if err := rejectSymlinkPath(path); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmpFile, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("unable to create temp file for %s: %w", path, err)
	}

	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(mode); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("unable to set permissions on temp key file for %s: %w", path, err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("unable to write temp key file for %s: %w", path, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("unable to sync temp key file for %s: %w", path, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("unable to close temp key file for %s: %w", path, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("unable to atomically write key file %s: %w", path, err)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("unable to stat key file %s after write: %w", path, err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use symlink key path %s", path)
	}
	if mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("unable to enforce permissions on key file %s: %w", path, err)
		}
	}

	cleanup = false
	return nil
}

func rejectSymlinkPath(path string) error {
	fileInfo, err := os.Lstat(path)
	if err == nil {
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write to symlink path %s", path)
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("unable to inspect key path %s: %w", path, err)
}
