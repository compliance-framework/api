package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type JWTKeyBootstrapAction string

const (
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
	privateKeyPath = strings.TrimSpace(privateKeyPath)
	publicKeyPath = strings.TrimSpace(publicKeyPath)

	if privateKeyPath == "" {
		return "", fmt.Errorf("private key path cannot be empty")
	}
	if publicKeyPath == "" {
		return "", fmt.Errorf("public key path cannot be empty")
	}
	if bitSize <= 0 {
		return "", fmt.Errorf("bit size must be greater than 0")
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
	if err := ensureParentDirectory(path); err != nil {
		return err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(path, privateKeyPEM, 0o600); err != nil {
		return fmt.Errorf("unable to write private key to %s: %w", path, err)
	}

	return nil
}

func writeRSAPublicKey(path string, key *rsa.PublicKey) error {
	if err := ensureParentDirectory(path); err != nil {
		return err
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	if err := os.WriteFile(path, publicKeyPEM, 0o644); err != nil {
		return fmt.Errorf("unable to write public key to %s: %w", path, err)
	}

	return nil
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
