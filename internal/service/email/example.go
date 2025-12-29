package email

import (
	"context"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email/types"
	"go.uber.org/zap"
)

// ExampleUsage demonstrates how to use the email service
func ExampleUsage() {
	// This is just an example - in real usage, you would get these from your app initialization
	logger := zap.NewExample().Sugar()

	// Load email configuration
	emailConfig, err := config.LoadEmailConfig("email.yaml")
	if err != nil {
		logger.Errorw("Failed to load email config", "error", err)
		return
	}

	// Create email service
	emailService, err := NewService(emailConfig, logger)
	if err != nil {
		logger.Errorw("Failed to create email service", "error", err)
		return
	}
	defer func() {
		if err := emailService.Close(); err != nil {
			logger.Errorw("Failed to close email service", "error", err)
		}
	}()

	// Check if email service is enabled
	if !emailService.IsEnabled() {
		logger.Info("Email service is not enabled")
		return
	}

	// Create a test message
	message := &types.Message{
		To:       []string{"recipient@example.com"},
		Subject:  "Test Email from Compliance Framework",
		TextBody: "This is a test email sent using the email service.",
		HTMLBody: "<p>This is a <strong>test email</strong> sent using the email service.</p>",
	}

	// Send the email
	result, err := emailService.Send(context.Background(), message)
	if err != nil {
		logger.Errorw("Failed to send email", "error", err)
		return
	}

	if result.Success {
		logger.Infow("Email sent successfully", "message_id", result.MessageID)
	} else {
		logger.Errorw("Failed to send email", "error", result.Error)
	}
}

// ExampleWithSpecificProvider shows how to use a specific email provider
func ExampleWithSpecificProvider() {
	logger := zap.NewExample().Sugar()

	// Load email configuration
	emailConfig, err := config.LoadEmailConfig("email.yaml")
	if err != nil {
		logger.Errorw("Failed to load email config", "error", err)
		return
	}

	// Create email service
	emailService, err := NewService(emailConfig, logger)
	if err != nil {
		logger.Errorw("Failed to create email service", "error", err)
		return
	}
	defer func() {
		if err := emailService.Close(); err != nil {
			logger.Errorw("Failed to close email service", "error", err)
		}
	}()

	// Create message
	message := &types.Message{
		To:       []string{"recipient@example.com"},
		Subject:  "Test Email via SMTP",
		TextBody: "This email is sent specifically via the SMTP provider.",
	}

	// Send using specific provider
	result, err := emailService.SendWithProvider(context.Background(), "smtp", message)
	if err != nil {
		logger.Errorw("Failed to send email via SMTP", "error", err)
		return
	}

	if result.Success {
		logger.Infow("Email sent successfully via SMTP", "message_id", result.MessageID)
	} else {
		logger.Errorw("Failed to send email via SMTP", "error", result.Error)
	}
}

// ExampleHealthCheck shows how to check if the email service is healthy
func ExampleHealthCheck() {
	logger := zap.NewExample().Sugar()

	// Load email configuration
	emailConfig, err := config.LoadEmailConfig("email.yaml")
	if err != nil {
		logger.Errorw("Failed to load email config", "error", err)
		return
	}

	// Create email service
	emailService, err := NewService(emailConfig, logger)
	if err != nil {
		logger.Errorw("Failed to create email service", "error", err)
		return
	}
	defer func() {
		if err := emailService.Close(); err != nil {
			logger.Errorw("Failed to close email service", "error", err)
		}
	}()

	// Check health
	err = emailService.IsHealthy(context.Background())
	if err != nil {
		logger.Errorw("Email service is not healthy", "error", err)
	} else {
		logger.Info("Email service is healthy")
	}

	// Get configuration
	config := emailService.GetConfig()
	logger.Infow("Email configuration",
		"enabled", config.Enabled,
		"default_provider", config.Provider,
	)
}
