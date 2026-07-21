package service

import (
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestBackfillLegacyNotificationSubscriptions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.User{}, &relational.UserNotificationSubscription{}))
	require.NoError(t, db.Exec(`ALTER TABLE ccf_users ADD COLUMN task_available_email_subscribed BOOLEAN`).Error)

	createUser := func(email string) relational.User {
		user := relational.User{
			Email:      email,
			FirstName:  "Test",
			LastName:   "User",
			AuthMethod: "password",
			IsActive:   true,
		}
		require.NoError(t, user.SetPassword("Pa55w0rd"))
		require.NoError(t, db.Create(&user).Error)
		return user
	}

	userWithLegacySubscription := createUser("legacy-1@example.com")
	userWithoutLegacySubscription := createUser("legacy-2@example.com")
	userWithExistingSubscription := createUser("legacy-3@example.com")

	require.NoError(t,
		db.Table("ccf_users").
			Where("id = ?", userWithLegacySubscription.ID.String()).
			Update("task_available_email_subscribed", true).
			Error,
	)
	require.NoError(t,
		db.Table("ccf_users").
			Where("id = ?", userWithExistingSubscription.ID.String()).
			Update("task_available_email_subscribed", true).
			Error,
	)

	existing := relational.UserNotificationSubscription{
		UserID:           userWithExistingSubscription.ID.String(),
		NotificationType: notification.SubscriptionGateTaskAvailable,
		Channels:         []string{notification.DeliveryChannelEmail},
	}
	require.NoError(t, db.Create(&existing).Error)

	require.NoError(t,
		backfillLegacyNotificationSubscriptions(
			db,
			"task_available_email_subscribed",
			notification.SubscriptionGateTaskAvailable,
			"task-available email",
		),
	)

	var rows []relational.UserNotificationSubscription
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 2)

	rowsByUserID := make(map[string]relational.UserNotificationSubscription, len(rows))
	for _, row := range rows {
		rowsByUserID[row.UserID] = row
	}

	assert.Equal(t, notification.SubscriptionGateTaskAvailable, rowsByUserID[userWithLegacySubscription.ID.String()].NotificationType)
	assert.Equal(t, []string{notification.DeliveryChannelEmail}, []string(rowsByUserID[userWithLegacySubscription.ID.String()].Channels))

	assert.Equal(t, notification.SubscriptionGateTaskAvailable, rowsByUserID[userWithExistingSubscription.ID.String()].NotificationType)
	assert.Equal(t, []string{notification.DeliveryChannelEmail}, []string(rowsByUserID[userWithExistingSubscription.ID.String()].Channels))

	require.NoError(t,
		backfillLegacyNotificationSubscriptions(
			db,
			"task_available_email_subscribed",
			notification.SubscriptionGateTaskAvailable,
			"task-available email",
		),
	)

	var count int64
	require.NoError(t, db.Model(&relational.UserNotificationSubscription{}).Count(&count).Error)
	assert.Equal(t, int64(2), count)

	var noSubscriptionCount int64
	require.NoError(t,
		db.Model(&relational.UserNotificationSubscription{}).
			Where("user_id = ?", userWithoutLegacySubscription.ID.String()).
			Count(&noSubscriptionCount).
			Error,
	)
	assert.Zero(t, noSubscriptionCount)
}

func TestBackfillLegacyRiskNotificationSubscriptions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.User{}, &relational.UserNotificationSubscription{}))
	require.NoError(t, db.Exec(`ALTER TABLE ccf_users ADD COLUMN risk_notifications_subscribed BOOLEAN`).Error)

	user := relational.User{
		Email:      "legacy-risk@example.com",
		FirstName:  "Legacy",
		LastName:   "Risk",
		AuthMethod: "password",
		IsActive:   true,
	}
	require.NoError(t, user.SetPassword("Pa55w0rd"))
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t,
		db.Table("ccf_users").
			Where("id = ?", user.ID.String()).
			Update("risk_notifications_subscribed", true).
			Error,
	)

	require.NoError(t, migrateLegacyRiskNotificationSubscriptions(db))

	var rows []relational.UserNotificationSubscription
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 1)
	assert.Equal(t, notification.SubscriptionGateRiskNotifications, rows[0].NotificationType)
	assert.Equal(t, []string{notification.DeliveryChannelEmail}, []string(rows[0].Channels))
	assert.Equal(t, user.ID.String(), rows[0].UserID)

	require.NoError(t, migrateLegacyRiskNotificationSubscriptions(db))

	var count int64
	require.NoError(t, db.Model(&relational.UserNotificationSubscription{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

func TestMigrateLegacySystemNotificationDestinationsBackfillsSlackDigestChannel(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	cfg := &config.Config{
		Slack: &config.SlackConfig{
			DigestChannel: "ccf-alerts",
		},
	}

	require.NoError(t, migrateLegacySystemNotificationDestinations(db, cfg, true))

	var rows []relational.SystemNotificationDestination
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 1)
	assert.Equal(t, notification.SubscriptionGateEvidenceDigest, rows[0].NotificationType)
	assert.Equal(t, notification.DeliveryChannelSlack, rows[0].Provider)
	target := rows[0].Target.Data()
	assert.Equal(t, "ccf-alerts", target.Address[slackprovider.AddressKeyChannel])
	assert.Equal(t, slackprovider.TargetTypeChannel, target.Address[slackprovider.AddressKeyTargetType])
}

func TestMigrateLegacySystemNotificationDestinationsDoesNotOverwriteExistingRow(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	existing := relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				slackprovider.AddressKeyChannel:    "existing-channel",
				slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
			},
		}),
	}
	require.NoError(t, db.Create(&existing).Error)

	cfg := &config.Config{
		Slack: &config.SlackConfig{
			DigestChannel: "env-channel",
		},
	}

	require.NoError(t, migrateLegacySystemNotificationDestinations(db, cfg, true))

	var rows []relational.SystemNotificationDestination
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 1)
	assert.Equal(t, "existing-channel", rows[0].Target.Data().Address[slackprovider.AddressKeyChannel])
}

func TestMigrateLegacySystemNotificationDestinationsSkipsWhenTableAlreadyExists(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	cfg := &config.Config{
		Slack: &config.SlackConfig{
			DigestChannel: "ccf-alerts",
		},
	}

	require.NoError(t, migrateLegacySystemNotificationDestinations(db, cfg, false))

	var count int64
	require.NoError(t, db.Model(&relational.SystemNotificationDestination{}).Count(&count).Error)
	assert.Zero(t, count)
}

// TestMigrateBackfillOfferingItemStatementIDs: legacy offering items written before the
// statement became the canonical anchor carry a NULL statement_id. The backfill derives it by
// walking provided_uuid -> export -> by_component for statement-anchored rows, and leaves it
// NULL for requirement-anchored ones (where no statement exists to derive) and for dangling
// provided-uuids — those are the rows Subscribe now rejects with a 422.
func TestMigrateBackfillOfferingItemStatementIDs(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.SSPExportOffering{},
		&relational.SSPExportOfferingItem{},
		&relational.ProvidedControlImplementation{},
		&relational.Export{},
		&relational.ByComponent{},
		&relational.Statement{},
		&relational.ImplementedRequirement{},
	))

	offering := relational.SSPExportOffering{Title: "Legacy offering"}
	require.NoError(t, db.Create(&offering).Error)

	requirement := relational.ImplementedRequirement{ControlId: "ac-2"}
	require.NoError(t, db.Create(&requirement).Error)
	statement := relational.Statement{ImplementedRequirementId: *requirement.ID, StatementId: "ac-2_smt.a"}
	require.NoError(t, db.Create(&statement).Error)

	// A statement-anchored export: the statement-id IS derivable.
	statementsType := "statements"
	statementBC := relational.ByComponent{ParentID: statement.ID, ParentType: &statementsType}
	require.NoError(t, db.Create(&statementBC).Error)
	statementExport := relational.Export{ByComponentId: *statementBC.ID}
	require.NoError(t, db.Create(&statementExport).Error)
	statementProvided := relational.ProvidedControlImplementation{ExportId: *statementExport.ID}
	require.NoError(t, db.Create(&statementProvided).Error)

	// A requirement-anchored export: the statement-id is NOT derivable.
	requirementsType := "implemented_requirements"
	requirementBC := relational.ByComponent{ParentID: requirement.ID, ParentType: &requirementsType}
	require.NoError(t, db.Create(&requirementBC).Error)
	requirementExport := relational.Export{ByComponentId: *requirementBC.ID}
	require.NoError(t, db.Create(&requirementExport).Error)
	requirementProvided := relational.ProvidedControlImplementation{ExportId: *requirementExport.ID}
	require.NoError(t, db.Create(&requirementProvided).Error)

	derivable := relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ProvidedUUID: *statementProvided.ID,
	}
	require.NoError(t, db.Create(&derivable).Error)

	undeivable := relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ProvidedUUID: *requirementProvided.ID,
	}
	require.NoError(t, db.Create(&undeivable).Error)

	dangling := relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ProvidedUUID: uuid.New(),
	}
	require.NoError(t, db.Create(&dangling).Error)

	alreadySet := relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ProvidedUUID: *statementProvided.ID,
		StatementID: func() *string { s := "ac-2_smt.z"; return &s }(),
	}
	require.NoError(t, db.Create(&alreadySet).Error)

	require.NoError(t, migrateBackfillOfferingItemStatementIDs(db))

	reload := func(id *uuid.UUID) relational.SSPExportOfferingItem {
		var item relational.SSPExportOfferingItem
		require.NoError(t, db.First(&item, "id = ?", id).Error)
		return item
	}

	backfilled := reload(derivable.ID)
	require.NotNil(t, backfilled.StatementID)
	assert.Equal(t, "ac-2_smt.a", *backfilled.StatementID)

	assert.Nil(t, reload(undeivable.ID).StatementID, "requirement-anchored: no statement to derive")
	assert.Nil(t, reload(dangling.ID).StatementID, "dangling provided-uuid: nothing to walk")

	untouched := reload(alreadySet.ID)
	require.NotNil(t, untouched.StatementID)
	assert.Equal(t, "ac-2_smt.z", *untouched.StatementID, "an item that already had a statement-id is not rewritten")

	// Idempotent: a second run changes nothing.
	require.NoError(t, migrateBackfillOfferingItemStatementIDs(db))
	assert.Equal(t, "ac-2_smt.a", *reload(derivable.ID).StatementID)
	assert.Nil(t, reload(undeivable.ID).StatementID)
}
