package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	DriverOptions = []string{"postgres"}
)

type Config struct {
	MongoURI           string
	AppPort            string
	DBDriver           string
	DBConnectionString string
	DBDebug            bool
	JWTSecret          string
	JWTPrivateKey      *rsa.PrivateKey
	JWTPublicKey       *rsa.PublicKey
}

func NewConfig(logger *zap.SugaredLogger) *Config {
	// for non-default but required variables, make sure the user is aware
	if !viper.IsSet("mongo_uri") {
		logger.Fatal("MONGO_URI is not set. Please set it in the environment or .env file.")
	}

	if !viper.IsSet("db_driver") {
		logger.Fatal(
			"CCF_DB_DRIVER is not set. Please set it in the environment or .env file. Expected values: ",
			strings.Join(DriverOptions, ", "),
		)
	}

	dbDriver := stripQuotes(strings.ToLower(viper.GetString("db_driver")))

	if !slices.Contains(DriverOptions, dbDriver) {
		logger.Fatal(
			"CCF_DB_DRIVER is set to an unsupported value: ",
			viper.GetString("db_driver"),
			". Supported values are: ",
			strings.Join(DriverOptions, ", "),
		)
	}

	if !viper.IsSet("db_connection") {
		logger.Fatal("CCF_DB_CONNECTION is not set. Please set it in the environment or .env file.")
	}

	if !viper.IsSet("jwt_secret") {
		logger.Warn("Using 'change-me' as JWT secret. This is insecure and should be changed in production.")
		viper.Set("jwt_secret", "change-me")
	}

	var (
		jwtPrivateKey *rsa.PrivateKey
		jwtPublicKey  *rsa.PublicKey
		err           error
	)
	if !viper.IsSet("jwt_private_key") || !viper.IsSet("jwt_public_key") {
		logger.Warn("No JWT key files have been provided. Generating new keys. Any original JWTs that weere generated with previous keys will no longer be valid.")
		jwtPrivateKey, jwtPublicKey, err = GenerateKeyPair(2048)
		if err != nil {
			logger.Fatalw("Failed to generate RSA key pair", "error", err)
		}
	} else {
		jwtPrivateKeyPath := stripQuotes(viper.GetString("jwt_private_key"))
		jwtPublicKeyPath := stripQuotes(viper.GetString("jwt_public_key"))

		jwtPrivateKey, err = loadRSAPrivateKey(jwtPrivateKeyPath)
		if err != nil {
			logger.Fatalw("Failed to load RSA private key", "error", err, "path", jwtPrivateKeyPath)
		}
		jwtPublicKey, err = loadRSAPublicKey(jwtPublicKeyPath)
		if err != nil {
			logger.Fatalw("Failed to load RSA public key", "error", err, "path", jwtPublicKeyPath)
		}
	}

	appPort := viper.GetString("app_port")
	if !strings.HasPrefix(appPort, ":") {
		appPort = ":" + appPort
	}

	return &Config{
		MongoURI:           viper.GetString("mongo_uri"),
		AppPort:            appPort,
		DBDriver:           dbDriver,
		DBConnectionString: stripQuotes(viper.GetString("db_connection")),
		DBDebug:            viper.GetBool("db_debug"),
		JWTSecret:          stripQuotes(viper.GetString("jwt_secret")),
		JWTPrivateKey:      jwtPrivateKey,
		JWTPublicKey:       jwtPublicKey,
	}

}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// LoadRSAPrivateKey reads an RSA private key from a PEM file at the given path.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	// Try PKCS1
	if block.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return key, nil
		}
	}
	// Try PKCS8
	privKeyIfc, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}
	privKey, ok := privKeyIfc.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key type is not RSA private")
	}
	return privKey, nil
}

// LoadRSAPublicKey reads an RSA public key from a PEM file at the given path.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read public key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	var pubIfc any
	if block.Type == "PUBLIC KEY" {
		pubIfc, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse PKIX public key: %w", err)
		}
	} else {
		pubIfc, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse PKCS1 public key: %w", err)
		}
	}
	pubKey, ok := pubIfc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key type is not RSA public")
	}
	return pubKey, nil
}

func GenerateKeyPair(bitsize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bitsize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}
	err = privKey.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("generated RSA private key is invalid: %w", err)
	}

	return privKey, &privKey.PublicKey, nil
}
