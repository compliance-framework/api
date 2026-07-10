package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// JobTypeLeverageDriftNotification is the single River job kind for both
// leverage_drifted and leverage_revoked notifications (BCH-1341) — which of the two
// notification.Kind values actually gets dispatched is decided at Work() time by
// notificationKindForReason, since a drift risk (risks.Risk with SourceType
// inherited-revoked) is the same underlying entity regardless of which trigger produced
// it.
const JobTypeLeverageDriftNotification = "leverage_drift_notification"

const (
	leverageDriftedNotificationKind = notification.Kind("leverage_drifted")
	leverageRevokedNotificationKind = notification.Kind("leverage_revoked")
)

// LeverageDriftNotificationArgs is the River job payload for one (risk, owner) pair,
// enqueued right after applyDriftToLink creates or reopens the drift risk.
type LeverageDriftNotificationArgs struct {
	Channel     string    `json:"channel,omitempty"`
	RiskID      uuid.UUID `json:"risk_id"`
	LinkID      uuid.UUID `json:"link_id"`
	OwnerUserID uuid.UUID `json:"owner_user_id"`
	Reason      string    `json:"reason,omitempty"`
}

func (LeverageDriftNotificationArgs) Kind() string { return JobTypeLeverageDriftNotification }

func (LeverageDriftNotificationArgs) Timeout() time.Duration { return 30 * time.Second }

// JobInsertOptionsForLeverageDriftNotification returns insert options for leverage drift
// notification jobs — mirrors JobInsertOptionsForRiskNotification's shape (email queue,
// deduped by args over a short window so a rapid re-drift/reopen doesn't spam).
func JobInsertOptionsForLeverageDriftNotification() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 5 * time.Minute,
		},
	}
}

// notificationKindForReason maps applyDriftToLink's free-text reason to one of the two
// notification kinds the ticket asks for: an explicit revocation (the upstream offering
// was revoked, or its leveraged authorization was deleted) is leverage_revoked; every
// other drift trigger (a content-changing version bump, or deprecation) is the softer
// leverage_drifted.
func notificationKindForReason(reason string) notification.Kind {
	if strings.Contains(reason, "revoked") {
		return leverageRevokedNotificationKind
	}
	return leverageDriftedNotificationKind
}

// leverageDriftNotificationModel is the template model for both leverage_drifted and
// leverage_revoked — deliberately small, reusing riskNotificationData (the drift risk is
// a plain risks.Risk row) rather than introducing a parallel data-loading path.
type leverageDriftNotificationModel struct {
	OwnerName string
	RiskTitle string
	SSPName   string
	Reason    string
	RiskURL   string
}

func (m leverageDriftNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"OwnerName": m.OwnerName,
		"RiskTitle": m.RiskTitle,
		"SSPName":   m.SSPName,
		"Reason":    m.Reason,
		"RiskURL":   m.RiskURL,
	}
}

func newLeverageDriftNotificationModel(userName string, data riskNotificationData, reason string) leverageDriftNotificationModel {
	ownerName := strings.TrimSpace(userName)
	if ownerName == "" {
		ownerName = strings.TrimSpace(data.OwnerName)
	}
	return leverageDriftNotificationModel{
		OwnerName: ownerName,
		RiskTitle: strings.TrimSpace(data.RiskTitle),
		SSPName:   strings.TrimSpace(data.SSPName),
		Reason:    strings.TrimSpace(reason),
		RiskURL:   strings.TrimSpace(data.RiskURL),
	}
}

func renderLeverageDriftedEmail(model leverageDriftNotificationModel) (emailprovider.TemplateContent, error) {
	return leverageDriftEmailContent(model, "leverage-drifted", "Leveraged control drifted"), nil
}

func renderLeverageRevokedEmail(model leverageDriftNotificationModel) (emailprovider.TemplateContent, error) {
	return leverageDriftEmailContent(model, "leverage-revoked", "Leveraged control revoked"), nil
}

func leverageDriftEmailContent(model leverageDriftNotificationModel, templateName, subjectPrefix string) emailprovider.TemplateContent {
	textBody := model.RiskTitle
	if model.Reason != "" {
		textBody = fmt.Sprintf("%s (%s)", textBody, model.Reason)
	}
	return emailprovider.TemplateContent{
		TemplateName: templateName,
		TemplateData: model.templateData(),
		Subject:      fmt.Sprintf("%s: %s", subjectPrefix, model.RiskTitle),
		TextBody:     textBody,
	}
}

func buildLeverageDriftNotificationRequest(
	args LeverageDriftNotificationArgs,
	userName string,
	data riskNotificationData,
) notification.Request {
	kind := notificationKindForReason(args.Reason)
	return newUserNotificationRequest(
		kind,
		args.OwnerUserID.String(),
		newLeverageDriftNotificationModel(userName, data, args.Reason),
		newJobDispatchOptions(string(kind), args.Channel, args.RiskID.String(), args.LinkID.String(), args.OwnerUserID.String()),
	)
}

// LeverageDriftNotificationWorker dispatches leverage_drifted/leverage_revoked
// notifications for a drift risk, mirroring RiskReviewDueReminderWorker's shape exactly
// — the drift risk is a plain risks.Risk row, so dispatchRiskReminderNotification's
// existing load-risk/load-owner/dispatch pipeline needs no changes to serve it.
type LeverageDriftNotificationWorker struct {
	db                         *gorm.DB
	userRepo                   UserRepository
	notificationServiceFactory *RiskNotificationServiceFactory
	webBaseURL                 string
	logger                     *zap.SugaredLogger
}

func NewLeverageDriftNotificationWorker(
	db *gorm.DB,
	userRepo UserRepository,
	webBaseURL string,
	notificationServiceFactory *RiskNotificationServiceFactory,
	logger *zap.SugaredLogger,
) *LeverageDriftNotificationWorker {
	return &LeverageDriftNotificationWorker{
		db:                         db,
		userRepo:                   userRepo,
		notificationServiceFactory: notificationServiceFactory,
		webBaseURL:                 webBaseURL,
		logger:                     logger,
	}
}

func (w *LeverageDriftNotificationWorker) Work(ctx context.Context, job *river.Job[LeverageDriftNotificationArgs]) error {
	args := job.Args
	if _, ok := normalizeRequestedDeliveryChannel(args.Channel); !ok {
		w.logger.Warnw("LeverageDriftNotificationWorker: invalid delivery channel, skipping",
			"risk_id", args.RiskID,
			"owner_user_id", args.OwnerUserID,
			"channel", args.Channel,
		)
		return nil
	}

	return dispatchRiskReminderNotification(
		ctx,
		w.db,
		w.userRepo,
		w.notificationServiceFactory,
		w.webBaseURL,
		w.logger,
		args.RiskID, args.OwnerUserID,
		func(userName string, data riskNotificationData) notification.Request {
			return requestWithSourceJobID(buildLeverageDriftNotificationRequest(args, userName, data), riverJobID(job))
		},
	)
}
