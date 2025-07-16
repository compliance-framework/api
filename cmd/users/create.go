package users

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"math/big"
)

func newUserAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new user",
		Long:  "This command allows you to add a new user to the system. You will be prompted for the user's email, first name, last name, and password.",
		Run:   addUser,
	}

	cmd.Flags().StringP("email", "e", "", "Email of the user (required)")
	cmd.MarkFlagRequired("email")

	cmd.Flags().StringP("first-name", "f", "", "First name of the user (required)")
	cmd.MarkFlagRequired("first-name")

	cmd.Flags().StringP("last-name", "l", "", "Last name of the user (required)")
	cmd.MarkFlagRequired("last-name")

	cmd.Flags().StringP("password", "p", "", "Password of the user")

	return cmd
}

func addUser(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	logger, err := zap.NewProduction()
	cobra.CheckErr(err)
	defer logger.Sync() // flushes buffer, if any
	sugar := logger.Sugar()

	config := config.NewConfig(sugar)
	db, err := service.ConnectSQLDb(ctx, config, sugar)

	if err != nil {
		sugar.Errorw("Failed to connect to database", "error", err)

	}

	email, err := cmd.Flags().GetString("email")
	if err != nil || email == "" {
		sugar.Error("Email is required")
		return
	}
	firstName, err := cmd.Flags().GetString("first-name")
	if err != nil || firstName == "" {
		sugar.Error("First name is required")
		return
	}
	lastName, err := cmd.Flags().GetString("last-name")
	if err != nil || lastName == "" {
		sugar.Error("Last name is required")
		return
	}

	var password string
	if ok := cmd.Flags().Changed("password"); ok {
		password, err = cmd.Flags().GetString("password")
		if err != nil {
			sugar.Errorw("Failed to get password", "error", err)
			return
		}
	} else {
		password, err = generatePassword(12) // Generate a random password of length 12
		if err != nil {
			sugar.Errorw("Failed to generate password", "error", err)
			return
		}
	}

	newUser := relational.User{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
	}

	newUser.SetPassword(password)
	if err = db.Create(&newUser).Error; err != nil {
		sugar.Errorw("Failed to create user", "error", err)
		return
	}
	sugar.Infow("User created successfully",
		"id", newUser.ID,
		"email", newUser.Email,
		"firstName", newUser.FirstName,
		"lastName", newUser.LastName,
		"password", password,
	)
}

func generatePassword(length int) (string, error) {
	const passwordCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"!@#$%^&*()-_=+[]{}<>?/"

	if length <= 0 {
		return "", errors.New("Length cannot be less than or equal to zero")
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(passwordCharset)))

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = passwordCharset[num.Int64()]
	}

	return string(result), nil
}
