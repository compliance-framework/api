package users

import (
	"context"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func updateUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an existing user given an email address",
		Long:  "This command allows you to update an existing user in the system. You will be prompted for the user's email, first name, last name, and password.",
		Run:   updateUser,
	}

	cmd.Flags().StringP("email", "e", "", "Email of the user (required)")
	cmd.MarkFlagRequired("email")

	cmd.Flags().StringP("first-name", "f", "", "First name of the user")

	cmd.Flags().StringP("last-name", "l", "", "Last name of the user")

	cmd.Flags().StringP("password", "p", "", "Password of the user (mutually exclusive with --generate-password)")
	cmd.Flags().Bool("generate-password", false, "Generate a random password for the user (mutually exclusive with --password)")

	cmd.MarkFlagsMutuallyExclusive("password", "generate-password")
	cmd.MarkFlagsOneRequired("first-name", "last-name", "password", "generate-password")

	return cmd
}

func updateUser(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger, err := zap.NewProduction()
	cobra.CheckErr(err)
	defer logger.Sync() // flushes buffer, if any
	sugar := logger.Sugar()

	config := config.NewConfig(sugar)
	db, err := service.ConnectSQLDb(ctx, config, sugar)

	if err != nil {
		sugar.Errorw("Failed to connect to database", "error", err)
		return
	}

	email, err := cmd.Flags().GetString("email")
	if err != nil || email == "" {
		sugar.Error("Email is required")
		return
	}

	var user relational.User
	if err = db.Where("email = ?", email).First(&user).Error; err != nil {
		sugar.Errorw("User not found", "email", email, "error", err)
		return
	}

	firstName, _ := cmd.Flags().GetString("first-name")
	if firstName != "" {
		user.FirstName = firstName
	}

	lastName, _ := cmd.Flags().GetString("last-name")
	if lastName != "" {
		user.LastName = lastName
	}

	password, _ := cmd.Flags().GetString("password")
	genPasswordFlag, _ := cmd.Flags().GetBool("generate-password")
	if genPasswordFlag {
		password, err = generatePassword(12)
		if err != nil {
			sugar.Errorw("Failed to generate password", "error", err)
			return
		}
		user.SetPassword(password)
	} else if password != "" {
		user.SetPassword(password)
	}

	if err = db.Save(&user).Error; err != nil {
		sugar.Errorw("Failed to update user", "error", err)
		return
	}
	sugar.Infow("User updated successfully",
		"id", user.ID,
		"email", user.Email,
		"firstName", user.FirstName,
		"lastName", user.LastName,
		"password", password,
	)
}
