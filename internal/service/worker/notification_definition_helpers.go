package worker

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
)

type notificationModelDecoder[T any] func(model any) (T, error)

type emailTemplateNotificationRenderer[T any] func(model T) (emailprovider.TemplateContent, error)

type slackMessageNotificationRenderer[T any] func(model T) (*slackprovider.Message, error)

func newNotificationModelDecoder[T any](modelName string) notificationModelDecoder[T] {
	return func(model any) (T, error) {
		return decodeNotificationModel[T](model, modelName)
	}
}

func decodeNotificationModel[T any](model any, modelName string) (T, error) {
	var zero T

	if typed, ok := model.(T); ok {
		return typed, nil
	}
	if typed, ok := model.(*T); ok {
		if typed == nil {
			return zero, fmt.Errorf("%s is required", modelName)
		}
		return *typed, nil
	}
	if model == nil {
		return zero, fmt.Errorf("%s is required", modelName)
	}

	return zero, fmt.Errorf("unexpected %s type %T", modelName, model)
}

func newTypedNotificationDefinition[T any](
	kind notification.Kind,
	subscriptionGate string,
	decode notificationModelDecoder[T],
	emailRender emailTemplateNotificationRenderer[T],
	slackRender slackMessageNotificationRenderer[T],
) notification.Definition {
	bindings := make([]notification.RendererBinding, 0, 2)
	if emailRender != nil {
		bindings = append(bindings, emailprovider.TemplateChannel(func(_ context.Context, model any) (emailprovider.TemplateContent, error) {
			typed, err := decode(model)
			if err != nil {
				return emailprovider.TemplateContent{}, err
			}

			return emailRender(typed)
		}))
	}
	if slackRender != nil {
		bindings = append(bindings, slackprovider.MessageChannel(func(_ context.Context, model any) (*slackprovider.Message, error) {
			typed, err := decode(model)
			if err != nil {
				return nil, err
			}

			return slackRender(typed)
		}))
	}

	return notification.NewDefinition(kind, subscriptionGate, bindings...)
}

func newTypedEmailOnlyNotificationDefinition[T any](
	kind notification.Kind,
	subscriptionGate string,
	decode notificationModelDecoder[T],
	emailRender emailTemplateNotificationRenderer[T],
) notification.Definition {
	return newTypedNotificationDefinition(kind, subscriptionGate, decode, emailRender, nil)
}

func newNotificationRequest(
	kind notification.Kind,
	audience notification.Audience,
	model any,
	options notification.DispatchOptions,
) notification.Request {
	return notification.Request{
		Kind: kind,
		Audiences: []notification.Audience{
			audience,
		},
		Model:   model,
		Options: options,
	}
}

func newUserNotificationRequest(
	kind notification.Kind,
	userID string,
	model any,
	options notification.DispatchOptions,
) notification.Request {
	return newNotificationRequest(
		kind,
		notification.Audience{User: &notification.UserAudience{UserID: strings.TrimSpace(userID)}},
		model,
		options,
	)
}

func newDirectEmailNotificationRequest(
	kind notification.Kind,
	emailAddress string,
	model any,
	options notification.DispatchOptions,
) notification.Request {
	return newNotificationRequest(
		kind,
		notification.Audience{
			Direct: &notification.DirectAudience{
				Provider: emailprovider.ChannelID,
				Address:  emailprovider.Identity(emailAddress),
			},
		},
		model,
		options,
	)
}

func newJobDispatchOptions(jobKind, requestedChannel string, correlationParts ...string) notification.DispatchOptions {
	trimmedJobKind := strings.TrimSpace(jobKind)
	parts := make([]string, 0, len(correlationParts)+1)
	for _, part := range correlationParts {
		if trimmedPart := strings.TrimSpace(part); trimmedPart != "" {
			parts = append(parts, trimmedPart)
		}
	}

	correlationID := ""
	if trimmedJobKind != "" && len(parts) > 0 {
		parts = append([]string{trimmedJobKind}, parts...)
		correlationID = strings.Join(parts, ":")
	}

	return notification.DispatchOptions{
		RequestedChannel: strings.TrimSpace(requestedChannel),
		CorrelationID:    correlationID,
		SourceJobKind:    trimmedJobKind,
	}
}
