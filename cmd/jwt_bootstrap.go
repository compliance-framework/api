package cmd

import (
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/spf13/viper"
)

const defaultJWTKeyBitSize = 2048

func bootstrapConfiguredJWTKeys(bitSize int, force bool) (config.JWTKeyBootstrapAction, string, string, bool, error) {
	privateKeyPath := strings.TrimSpace(viper.GetString("jwt_private_key"))
	publicKeyPath := strings.TrimSpace(viper.GetString("jwt_public_key"))

	if privateKeyPath == "" || publicKeyPath == "" {
		return "", "", "", false, nil
	}

	action, err := runJWTBootstrap(privateKeyPath, publicKeyPath, bitSize, force)
	if err != nil {
		return "", privateKeyPath, publicKeyPath, true, err
	}

	return action, privateKeyPath, publicKeyPath, true, nil
}

func resolveJWTKeyPathsForBootstrap(privateKeyPath, publicKeyPath string) (string, string) {
	privateKeyPath = strings.TrimSpace(privateKeyPath)
	publicKeyPath = strings.TrimSpace(publicKeyPath)

	if privateKeyPath == "" {
		privateKeyPath = strings.TrimSpace(viper.GetString("jwt_private_key"))
	}
	if publicKeyPath == "" {
		publicKeyPath = strings.TrimSpace(viper.GetString("jwt_public_key"))
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
