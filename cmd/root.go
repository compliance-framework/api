package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/compliance-framework/api/cmd/dashboards"
	"github.com/compliance-framework/api/cmd/oscal"
	"github.com/compliance-framework/api/cmd/seed"
	"github.com/compliance-framework/api/cmd/users"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:   "api",
		Short: "Compliance Framework API",
	}
)

func setDefaultEnvironmentVariables() {
	viper.SetDefault("app_port", ":8080")
	viper.SetDefault("db_debug", "false")
	viper.SetDefault("metrics_enabled", "true")
	viper.SetDefault("metrics_port", ":9090")
	viper.SetDefault("evidence_default_expiry_months", "1")
	viper.SetDefault("digest_enabled", "true")
	viper.SetDefault("digest_schedule", "@weekly")
}

func bindEnvironmentVariables() {
	viper.SetEnvPrefix("ccf")
	viper.MustBindEnv("app_port")
	viper.MustBindEnv("db_driver")
	viper.MustBindEnv("environment")
	viper.MustBindEnv("db_connection")
	viper.MustBindEnv("db_debug")
	viper.MustBindEnv("jwt_secret")
	viper.MustBindEnv("jwt_private_key")
	viper.MustBindEnv("jwt_public_key")
	viper.MustBindEnv("api_allowed_origins")
	viper.MustBindEnv("web_base_url")
	viper.MustBindEnv("sso_config")
	viper.MustBindEnv("email_config")
	viper.MustBindEnv("workflow_config")
	viper.MustBindEnv("risk_config")
	viper.MustBindEnv("metrics_enabled")
	viper.MustBindEnv("metrics_port")
	viper.MustBindEnv("use_dev_logger")
	viper.MustBindEnv("evidence_default_expiry_months")
	viper.MustBindEnv("digest_enabled")
	viper.MustBindEnv("digest_schedule")
}

func init() {
	// Initialize viper & godotenv
	if err := godotenv.Load(".env"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			panic("Error loading .env file: " + err.Error())
		}
	}

	setDefaultEnvironmentVariables()
	bindEnvironmentVariables()

	// Global persistent flags
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable debug mode for the database connection")
	if err := viper.BindPFlag("db_debug", rootCmd.PersistentFlags().Lookup("debug")); err != nil {
		panic(err)
	}

	// Subcommands
	rootCmd.AddCommand(RunCmd)
	rootCmd.AddCommand(oscal.RootCmd)
	rootCmd.AddCommand(users.RootCmd)
	rootCmd.AddCommand(seed.RootCmd)
	rootCmd.AddCommand(newMigrateCMD())
	rootCmd.AddCommand(newBootstrapCMD())
	rootCmd.AddCommand(dashboards.RootCmd)
	rootCmd.AddCommand(DigestCmd)
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error executing root command:", err)
		return err
	}
	return nil
}
