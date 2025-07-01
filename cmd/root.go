package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/compliance-framework/configuration-service/cmd/oscal"
	"github.com/compliance-framework/configuration-service/cmd/seed"
	"github.com/compliance-framework/configuration-service/cmd/users"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:   "conf-service",
		Short: "Compliance Framework Configuration Service",
	}
)

func configSetDefaults() {
	viper.SetDefault("app_port", ":8080")
	viper.SetDefault("db_debug", "false")
}

func configEnvKeys() {
	viper.SetEnvPrefix("ccf")
	viper.BindEnv("mongo_uri", "MONGO_URI")
	viper.BindEnv("app_port", "APP_PORT")
	viper.BindEnv("db_driver")
	viper.BindEnv("db_connection")
	viper.BindEnv("db_debug")
	viper.BindEnv("jwt_secret")
	viper.BindEnv("jwt_private_key")
	viper.BindEnv("jwt_public_key")
	viper.BindEnv("api_allowed_origins")
}

func init() {
	// Initialize viper & godotenv
	if err := godotenv.Load(".env"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			panic("Error loading .env file: " + err.Error())
		}
	}
	configSetDefaults()
	configEnvKeys()

	// Global persistent flags
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable debug mode for the database connection")
	viper.BindPFlag("db_debug", rootCmd.PersistentFlags().Lookup("debug"))

	// Subcommands
	rootCmd.AddCommand(RunCmd)
	rootCmd.AddCommand(oscal.RootCmd)
	rootCmd.AddCommand(users.RootCmd)
	rootCmd.AddCommand(seed.RootCmd)
	rootCmd.AddCommand(newMigrateCMD())
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error executing root command:", err)
		return err
	}
	return nil
}
