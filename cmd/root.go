package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/compliance-framework/configuration-service/cmd/oscal"
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

}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error executing root command:", err)
		return err
	}
	return nil
}
