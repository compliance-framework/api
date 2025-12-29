package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/compliance-framework/api/internal/config"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"go.uber.org/zap"
)

type sesClient interface {
	SendEmail(context.Context, *sesv2.SendEmailInput, ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
	GetAccount(context.Context, *sesv2.GetAccountInput, ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error)
}

type realSESClient struct {
	client *sesv2.Client
}

func (r *realSESClient) SendEmail(ctx context.Context, input *sesv2.SendEmailInput, optFns ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	return r.client.SendEmail(ctx, input, optFns...)
}

func (r *realSESClient) GetAccount(ctx context.Context, input *sesv2.GetAccountInput, optFns ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	return r.client.GetAccount(ctx, input, optFns...)
}

type sesProvider struct {
	config *config.EmailProviderConfig
	logger *zap.SugaredLogger
	client sesClient
}

// NewSESProvider creates a new AWS SES email provider
func NewSESProvider(ctx context.Context, cfg *config.EmailProviderConfig, logger *zap.SugaredLogger) (emailtypes.Provider, error) {
	if strings.ToLower(cfg.Provider) != "ses" {
		return nil, fmt.Errorf("invalid provider type for SES: %s", cfg.Provider)
	}

	// Create AWS session
	cfgAWS, err := createAWSConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %w", err)
	}

	// Create SES client
	client := sesv2.NewFromConfig(cfgAWS)

	provider := &sesProvider{
		config: cfg,
		logger: logger,
		client: &realSESClient{client: client},
	}

	// Test connection during initialization
	if err := provider.IsHealthy(ctx); err != nil {
		return nil, fmt.Errorf("SES connection test failed: %w", err)
	}

	logger.Infow("SES provider initialized", "region", cfg.Host, "from", cfg.From)
	return provider, nil
}

func (p *sesProvider) Send(ctx context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error) {
	if message == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}

	// Set default from address if not provided in message
	from := message.From
	if from == "" {
		from = p.config.From
	}
	if from == "" {
		return nil, fmt.Errorf("no from address specified")
	}

	// Validate recipients
	if len(message.To) == 0 {
		return nil, fmt.Errorf("no recipients specified")
	}

	// Build SES input
	input := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(from),
		Destination: &types.Destination{
			ToAddresses: message.To,
		},
		Content: p.buildEmailContent(message),
	}

	// Add CC recipients if provided
	if len(message.Cc) > 0 {
		input.Destination.CcAddresses = message.Cc
	}

	// Add BCC recipients if provided
	if len(message.Bcc) > 0 {
		input.Destination.BccAddresses = message.Bcc
	}

	// Send email
	result, err := p.client.SendEmail(ctx, input)
	if err != nil {
		p.logger.Errorw("Failed to send email via SES", "error", err, "to", message.To)
		return &emailtypes.SendResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	messageId := ""
	if result.MessageId != nil {
		messageId = *result.MessageId
	}

	p.logger.Infow("Email sent successfully via SES", "to", message.To, "subject", message.Subject, "message_id", messageId)
	return &emailtypes.SendResult{
		Success:   true,
		MessageID: messageId,
	}, nil
}

func (p *sesProvider) SendTemplate(ctx context.Context, template string, data interface{}, message *emailtypes.Message) (*emailtypes.SendResult, error) {
	// SES supports templating, but this would require template setup in AWS
	// For now, fall back to regular email sending
	return p.Send(ctx, message)
}

func (p *sesProvider) GetProviderConfig() *config.EmailProviderConfig {
	return p.config
}

func (p *sesProvider) GetName() string {
	return p.config.Name
}

func (p *sesProvider) GetType() string {
	return "ses"
}

func (p *sesProvider) IsHealthy(ctx context.Context) error {
	// Test SES connectivity by getting account information
	_, err := p.client.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		return fmt.Errorf("SES health check failed: %w", err)
	}
	return nil
}

func (p *sesProvider) Close() error {
	// SES client doesn't require explicit cleanup
	return nil
}

func (p *sesProvider) buildEmailContent(message *emailtypes.Message) *types.EmailContent {
	subject := types.Content{
		Data:    aws.String(message.Subject),
		Charset: aws.String("UTF-8"),
	}

	if message.HTMLBody != "" && message.TextBody != "" {
		var htmlBody types.Content
		htmlBody.Data = aws.String(message.HTMLBody)
		htmlBody.Charset = aws.String("UTF-8")

		var textBody types.Content
		textBody.Data = aws.String(message.TextBody)
		textBody.Charset = aws.String("UTF-8")

		var body types.Body
		body.Html = &htmlBody
		body.Text = &textBody

		return &types.EmailContent{
			Simple: &types.Message{
				Subject: &subject,
				Body:    &body,
			},
		}
	} else if message.HTMLBody != "" {
		// HTML only
		var htmlBody types.Content
		htmlBody.Data = aws.String(message.HTMLBody)
		htmlBody.Charset = aws.String("UTF-8")

		var body types.Body
		body.Html = &htmlBody

		return &types.EmailContent{
			Simple: &types.Message{
				Subject: &subject,
				Body:    &body,
			},
		}
	} else {
		// Text only
		var textBody types.Content
		textBody.Data = aws.String(message.TextBody)
		textBody.Charset = aws.String("UTF-8")

		var body types.Body
		body.Text = &textBody

		return &types.EmailContent{
			Simple: &types.Message{
				Subject: &subject,
				Body:    &body,
			},
		}
	}
}

// createAWSConfig creates an AWS config with the provided configuration
func createAWSConfig(ctx context.Context, cfg *config.EmailProviderConfig) (aws.Config, error) {
	// Load default AWS config
	cfgAWS, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Host)) // Using Host field to store AWS region
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Override credentials if provided
	if cfg.Username != "" && cfg.Password != "" {
		// Using Username for AccessKeyID and Password for SecretAccessKey
		cfgAWS.Credentials = credentials.NewStaticCredentialsProvider(cfg.Username, cfg.Password, "")
	}

	return cfgAWS, nil
}
