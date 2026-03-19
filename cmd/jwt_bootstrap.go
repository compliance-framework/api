package cmd

import (
	"errors"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/spf13/viper"
)

const defaultJWTKeyBitSize = 2048

func bootstrapConfiguredJWTKeys(bitSize int, force bool) (config.JWTKeyBootstrapAction, string, string, bool, error) {
	privateKeyConfigured := viper.IsSet("jwt_private_key")
	publicKeyConfigured := viper.IsSet("jwt_public_key")

	if !privateKeyConfigured || !publicKeyConfigured {
		return "", "", "", false, nil
	}

	privateKeyPath := normalizePathValue(viper.GetString("jwt_private_key"))
	publicKeyPath := normalizePathValue(viper.GetString("jwt_public_key"))

	if privateKeyPath == "" || publicKeyPath == "" {
		return "", privateKeyPath, publicKeyPath, true, configErrorForEmptyJWTKeyPath()
	}

	action, err := runJWTBootstrap(privateKeyPath, publicKeyPath, bitSize, force)
	if err != nil {
		return "", privateKeyPath, publicKeyPath, true, err
	}

	return action, privateKeyPath, publicKeyPath, true, nil
}

func resolveJWTKeyPathsForBootstrap(privateKeyPath, publicKeyPath string) (string, string) {
	privateKeyPath = normalizePathValue(privateKeyPath)
	publicKeyPath = normalizePathValue(publicKeyPath)

	if privateKeyPath == "" {
		privateKeyPath = normalizePathValue(viper.GetString("jwt_private_key"))
	}
	if publicKeyPath == "" {
		publicKeyPath = normalizePathValue(viper.GetString("jwt_public_key"))
	}

	if privateKeyPath == "" {
		privateKeyPath = "private.pem"
	}
	if publicKeyPath == "" {
		publicKeyPath = "public.pem"
	}

	return privateKeyPath, publicKeyPath
}

func runJWTBootstrap(privateKeyPath, publicKeyPath string, bitSize int, force bool) (config.JWTKeyBootstrapAction, error) {
	return config.BootstrapJWTKeyPair(privateKeyPath, publicKeyPath, bitSize, force)
}

func normalizePathValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return strings.TrimSpace(value)
}

func configErrorForEmptyJWTKeyPath() error {
	return errors.New(
		"CCF_JWT_PRIVATE_KEY and CCF_JWT_PUBLIC_KEY are set but one or both are empty. " +
			"Set both to non-empty paths, or remove/comment out both to use in-memory key generation",
	)
}
