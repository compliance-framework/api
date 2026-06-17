package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	poamrel "github.com/compliance-framework/api/internal/service/relational/poam"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const legacyNotificationBackfillBatchSize = 1000

type legacySubscribedUser struct {
	ID string `gorm:"column:id"`
}

func MigrateUp(db *gorm.DB) error {
	return MigrateUpWithConfig(db, nil)
}

func MigrateUpWithConfig(db *gorm.DB, cfg *config.Config) error {
	workflowEntities := workflows.GetWorkflowEntities()
	systemNotificationDestinationTableExists := db.Migrator().HasTable(&relational.SystemNotificationDestination{})

	err := db.AutoMigrate(
		&relational.ResponsiblePartyParties{},
		&relational.Location{},
		&relational.Party{},
		&relational.BackMatterResource{},
		&relational.BackMatter{},
		&relational.Role{},
		&relational.Revision{},
		&relational.ResponsibleParty{},
		&relational.ResponsibleRole{},
		&relational.Action{},
		&relational.Metadata{},
		&relational.Group{},
		&relational.Control{},
		&relational.Catalog{},
		&relational.ControlStatementImplementation{},
		&relational.ImplementedRequirementControlImplementation{},
		&relational.ControlImplementationSet{},
		&relational.ComponentDefinition{},
		&relational.Capability{},
		&relational.DefinedComponent{},
		&relational.Diagram{},
		&relational.DataFlow{},
		&relational.NetworkArchitecture{},
		&relational.AuthorizationBoundary{},
		&relational.InformationType{},
		&relational.SystemInformation{},
		&relational.SystemCharacteristics{},
		&relational.AuthorizedPrivilege{},
		&relational.SystemUser{},
		&relational.LeveragedAuthorization{},
		&relational.SystemComponent{},
		&relational.ImplementedComponent{},
		&relational.InventoryItem{},
		&relational.SystemImplementation{},
		&relational.ControlImplementationResponsibility{},
		&relational.ProvidedControlImplementation{},
		&relational.SatisfiedControlImplementationResponsibility{},
		&relational.Export{},
		&relational.InheritedControlImplementation{},
		&relational.ByComponent{},
		&relational.Statement{},
		&relational.ImplementedRequirement{},
		&relational.ControlImplementation{},
		&relational.SystemSecurityPlan{},
		&relational.SSPProfile{},
		&relational.AuthorizationBoundary{},
		&relational.NetworkArchitecture{},
		&relational.DataFlow{},
		&relational.Diagram{},
		&relational.AssessmentPlan{},
		&relational.LocalDefinitions{},
		&relational.LocalObjective{},
		&relational.Task{},
		&relational.TaskDependency{},
		&relational.AssessmentAsset{},
		&relational.AssessmentPlatform{},
		&relational.UsesComponent{},
		&relational.AssessmentSubject{},
		&relational.SelectSubjectById{},
		&relational.AssociatedActivity{},
		&relational.Activity{},
		&relational.Step{},
		&relational.ReviewedControls{},
		&relational.ControlSelection{},
		&relational.ControlObjectiveSelection{},
		&relational.SelectObjectiveById{},

		// POAM entities
		&relational.PlanOfActionAndMilestones{},
		&relational.PlanOfActionAndMilestonesLocalDefinitions{},
		&relational.PoamItem{},
		&relational.Risk{},
		&relational.Observation{},
		&relational.Finding{},
		&riskrel.Risk{},
		&riskrel.RiskScore{},
		&riskrel.RiskEvent{},
		&riskrel.RiskReview{},
		&riskrel.RiskEvidenceLink{},
		&riskrel.RiskControlLink{},
		&riskrel.RiskComponentLink{},
		&riskrel.RiskSubjectLink{},
		&riskrel.RiskOwnerAssignment{},
		&riskrel.RiskThreatRef{},
		&riskrel.RiskRemediationTemplate{},
		&riskrel.RiskRemediationTask{},
		&riskrel.AssessmentSubjectLabel{},
		&riskrel.InventoryItemLabel{},
		&riskrel.SystemComponentLabel{},
		&riskrel.ComponentDefinitionLabel{},
		&templaterel.RiskTemplate{},
		&templaterel.RiskTemplateThreatRef{},
		&templaterel.RiskTemplateLabelSchemaField{},
		&templaterel.RemediationTemplate{},
		&templaterel.RemediationTask{},
		&templaterel.SubjectTemplate{},
		&templaterel.SubjectTemplateSelectorLabel{},
		&templaterel.SubjectTemplateLabelSchemaField{},
		&templaterel.AssessmentSubjectIdentity{},
		&templaterel.SystemComponentIdentity{},
		&templaterel.ComponentDefinitionIdentity{},

		&relational.Profile{},
		&relational.Import{},
		&relational.Merge{},
		&relational.Modify{},
		&relational.ParameterSetting{},
		&relational.Alteration{},
		&relational.Addition{},
		&relational.SelectControlById{},
		&relational.ResponsibleRole{},
		&relational.AssessmentResult{},
		&relational.Activity{},
		&relational.Step{},
		&relational.Task{},
		&relational.AssessedControlsSelectControlById{},
		&relational.Result{},
		&relational.AssessmentLog{},
		&relational.AssessmentLogEntry{},
		&relational.TermsAndConditions{},
		&relational.Attestation{},

		// Compliance-Framework - not related to OSCAL
		&relational.SSOUserLink{},
		&relational.SlackLinkAttempt{},
		&relational.SlackUserLink{},
		&poamrel.PoamItem{},
		&poamrel.PoamItemMilestone{},
		&poamrel.PoamItemRiskLink{},
		&poamrel.PoamItemEvidenceLink{},
		&poamrel.PoamItemControlLink{},
		&poamrel.PoamItemFindingLink{},
		&relational.User{},
		&relational.Agent{},
		&relational.AgentServiceAccountKey{},
		&relational.AgentAuthEvent{},
		&relational.UserNotificationSubscription{},
		&relational.SystemNotificationDestination{},
		&Heartbeat{},
		&relational.Evidence{},
		&relational.Labels{},
		&relational.SelectSubjectById{},
		&relational.Filter{},
		&suggestionrel.DashboardSuggestionRun{},
		&suggestionrel.DashboardSuggestionRunCell{},
		&suggestionrel.DashboardSuggestion{},
		&suggestionrel.DashboardSuggestionEvent{},
		&relational.Step{},
	)
	if err != nil {
		return err
	}

	// Add workflow entities separately to avoid argument limit
	for _, entity := range workflowEntities {
		if err := db.AutoMigrate(entity); err != nil {
			return err
		}
	}
	if err := riskrel.EnsureIndexes(db); err != nil {
		return err
	}

	if err := migrateLegacySystemNotificationDestinations(db, cfg, !systemNotificationDestinationTableExists); err != nil {
		return err
	}
	if err := migrateLegacyTaskAvailableEmailSubscriptions(db); err != nil {
		return err
	}
	if err := migrateLegacyDigestSubscriptions(db); err != nil {
		return err
	}
	if err := migrateLegacyTaskDailyDigestSubscriptions(db); err != nil {
		return err
	}
	if err := migrateLegacyRiskNotificationSubscriptions(db); err != nil {
		return err
	}
	if err := migrateSSPProfileIDToJoinTable(db); err != nil {
		return err
	}

	// Create functional index for case-insensitive control_id lookups in filter_controls join table
	// This improves performance of UPPER(control_id) queries in the suggestion service
	// Note: GORM doesn't support functional indexes via struct tags, so we use raw SQL

	// Using db.Name() as opposed to `db.Dialector.Name()`
	// Having the second one is a violation of staticcheck rule QF1008.
	// ref: https://staticcheck.dev/docs/checks/#QF1008
	if db.Name() == "postgres" {
		// PostgreSQL supports functional indexes
		if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_filter_controls_upper_control_id ON filter_controls (UPPER(control_id))`).Error; err != nil {
			return err
		}

		// Add partial unique index for system_components to ensure idempotency
		// This prevents duplicate (system_implementation_id, defined_component_id) pairs
		// while still allowing multiple rows with NULL defined_component_id
		// The WHERE clause makes this a partial index that only enforces uniqueness when defined_component_id IS NOT NULL
		if err := db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_system_components_unique_impl_defined
			ON system_components (system_implementation_id, defined_component_id)
			WHERE defined_component_id IS NOT NULL
		`).Error; err != nil {
			return err
		}

		// Align control_catalog_id join columns (historically text) with
		// controls.catalog_id, which is uuid.
		// The mismatch forced every catalog-scoped join (suggestion service, filter handler,
		// risk evidence worker) to CAST around it. Idempotent and safe to run every boot:
		// it only fires while the column is still text. NULLIF guards any legacy empty
		// strings that ''::uuid would otherwise reject; real values are uuid.UUID.String().
		if err := db.Exec(`
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'filter_controls'
			      AND column_name = 'control_catalog_id'
			      AND data_type = 'text'
			  ) THEN
			    ALTER TABLE filter_controls
			      ALTER COLUMN control_catalog_id TYPE uuid
			      USING NULLIF(control_catalog_id, '')::uuid;
			  END IF;
			END $$;
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'profile_controls'
			      AND column_name = 'control_catalog_id'
			      AND data_type = 'text'
			  ) THEN
			    ALTER TABLE profile_controls
			      ALTER COLUMN control_catalog_id TYPE uuid
			      USING NULLIF(control_catalog_id, '')::uuid;
			  END IF;
			END $$;
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'filters'
			      AND column_name = 'ssp_id'
			  ) AND NOT EXISTS (
			    SELECT 1 FROM pg_constraint
			    WHERE conname = 'fk_filters_system_security_plan'
			  ) THEN
			    ALTER TABLE filters
			      ADD CONSTRAINT fk_filters_system_security_plan
			      FOREIGN KEY (ssp_id)
			      REFERENCES system_security_plans(id)
			      ON DELETE CASCADE;
			  END IF;
			END $$;
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'dashboard_suggestion_run_cells'
			      AND column_name = 'run_id'
			  ) AND NOT EXISTS (
			    SELECT 1 FROM pg_constraint
			    WHERE conname = 'fk_dashboard_suggestion_run_cells_run'
			  ) THEN
			    ALTER TABLE dashboard_suggestion_run_cells
			      ADD CONSTRAINT fk_dashboard_suggestion_run_cells_run
			      FOREIGN KEY (run_id)
			      REFERENCES dashboard_suggestion_runs(id)
			      ON DELETE CASCADE;
			  END IF;
			END $$;
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'dashboard_suggestions'
			      AND column_name = 'run_id'
			  ) AND NOT EXISTS (
			    SELECT 1 FROM pg_constraint
			    WHERE conname = 'fk_dashboard_suggestions_run'
			  ) THEN
			    ALTER TABLE dashboard_suggestions
			      ADD CONSTRAINT fk_dashboard_suggestions_run
			      FOREIGN KEY (run_id)
			      REFERENCES dashboard_suggestion_runs(id)
			      ON DELETE CASCADE;
			  END IF;
			END $$;
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_suggestions_unique_pending
			ON dashboard_suggestions (ssp_id, control_catalog_id, control_id, label_set_hash)
			WHERE status = 'pending'
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_suggestions_unique_pending_filter_labels
			ON dashboard_suggestions (ssp_id, control_catalog_id, control_id, proposed_filter_label_set)
			WHERE status = 'pending'
			  AND proposed_filter_label_set IS NOT NULL
			  AND proposed_filter_label_set <> 'null'::jsonb
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_suggestion_runs_unique_active
			ON dashboard_suggestion_runs (ssp_id)
			WHERE status IN ('pending', 'running')
		`).Error; err != nil {
			return err
		}
	}
	// For SQLite and other databases we do not create functional/unique indexes here.
	// They will rely on their default query plans; a plain index on control_id
	// is typically not used for expression predicates like UPPER(control_id) without an expression index.

	return err
}

func migrateLegacySystemNotificationDestinations(db *gorm.DB, cfg *config.Config, tableJustCreated bool) error {
	if !tableJustCreated {
		db.Logger.Info(
			context.Background(),
			"Skipping legacy system notification destination migration: ccf_system_notification_destinations already exists",
		)
		return nil
	}

	channel := legacySlackDigestChannel(cfg)
	if channel == "" {
		db.Logger.Info(
			context.Background(),
			"Skipping legacy system notification destination migration: CCF_SLACK_DIGEST_CHANNEL is empty",
		)
		return nil
	}

	var existing relational.SystemNotificationDestination
	if err := db.
		Where("notification_type = ? AND provider = ?", notification.SubscriptionGateEvidenceDigest, notification.DeliveryChannelSlack).
		First(&existing).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to query existing system notification destination %q: %w", slackprovider.ConfiguredDestinationDigestChan, err)
		}

		row := relational.SystemNotificationDestination{
			NotificationType: notification.SubscriptionGateEvidenceDigest,
			Provider:         notification.DeliveryChannelSlack,
			Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
				Address: map[string]string{
					slackprovider.AddressKeyChannel:    channel,
					slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
				},
			}),
		}
		if err := db.Create(&row).Error; err != nil {
			return fmt.Errorf("failed to migrate legacy system notification destination %q: %w", slackprovider.ConfiguredDestinationDigestChan, err)
		}

		db.Logger.Info(
			context.Background(),
			"Migrated legacy Slack digest channel into ccf_system_notification_destinations",
		)
		return nil
	}

	db.Logger.Info(
		context.Background(),
		"Skipping legacy system notification destination migration: configured destination already exists",
	)
	return nil
}

func legacySlackDigestChannel(cfg *config.Config) string {
	if cfg != nil && cfg.Slack != nil {
		if channel := strings.TrimSpace(cfg.Slack.DigestChannel); channel != "" {
			return channel
		}
	}

	return strings.TrimSpace(os.Getenv("CCF_SLACK_DIGEST_CHANNEL"))
}

func migrateLegacyTaskAvailableEmailSubscriptions(db *gorm.DB) error {
	// Nothing to migrate after the legacy column has been removed.
	if !db.Migrator().HasColumn(&relational.User{}, "task_available_email_subscribed") {
		db.Logger.Info(
			context.Background(),
			"Skipping legacy task-available email subscription migration: ccf_users.task_available_email_subscribed is already absent",
		)
		return nil
	}

	if err := backfillLegacyNotificationSubscriptions(
		db,
		"task_available_email_subscribed",
		notification.SubscriptionGateTaskAvailable,
		"task-available email",
	); err != nil {
		return err
	}

	return db.Migrator().DropColumn(&relational.User{}, "task_available_email_subscribed")
}

func migrateLegacyDigestSubscriptions(db *gorm.DB) error {
	// Nothing to migrate after the legacy column has been removed.
	if !db.Migrator().HasColumn(&relational.User{}, "digest_subscribed") {
		db.Logger.Info(
			context.Background(),
			"Skipping legacy evidence digest subscription migration: ccf_users.digest_subscribed is already absent",
		)
		return nil
	}

	if err := backfillLegacyNotificationSubscriptions(
		db,
		"digest_subscribed",
		notification.SubscriptionGateEvidenceDigest,
		"evidence digest",
	); err != nil {
		return err
	}

	return db.Migrator().DropColumn(&relational.User{}, "digest_subscribed")
}

func migrateLegacyTaskDailyDigestSubscriptions(db *gorm.DB) error {
	// Nothing to migrate after the legacy column has been removed.
	if !db.Migrator().HasColumn(&relational.User{}, "task_daily_digest_subscribed") {
		db.Logger.Info(
			context.Background(),
			"Skipping legacy task daily digest subscription migration: ccf_users.task_daily_digest_subscribed is already absent",
		)
		return nil
	}

	if err := backfillLegacyNotificationSubscriptions(
		db,
		"task_daily_digest_subscribed",
		notification.SubscriptionGateTaskDailyDigest,
		"task daily digest",
	); err != nil {
		return err
	}

	return db.Migrator().DropColumn(&relational.User{}, "task_daily_digest_subscribed")
}

func migrateLegacyRiskNotificationSubscriptions(db *gorm.DB) error {
	// Nothing to migrate after the legacy column has been removed.
	if !db.Migrator().HasColumn(&relational.User{}, "risk_notifications_subscribed") {
		db.Logger.Info(
			context.Background(),
			"Skipping legacy risk notification subscription migration: ccf_users.risk_notifications_subscribed is already absent",
		)
		return nil
	}

	if err := backfillLegacyNotificationSubscriptions(
		db,
		"risk_notifications_subscribed",
		notification.SubscriptionGateRiskNotifications,
		"risk notifications",
	); err != nil {
		return err
	}

	return db.Migrator().DropColumn(&relational.User{}, "risk_notifications_subscribed")
}

func backfillLegacyNotificationSubscriptions(db *gorm.DB, legacyColumn string, notificationType string, legacyLabel string) error {
	var subscribedUsers []legacySubscribedUser

	return db.Table("ccf_users").
		Select("id").
		Where(legacyColumn+" = ?", true).
		FindInBatches(&subscribedUsers, legacyNotificationBackfillBatchSize, func(_ *gorm.DB, batch int) error {
			rows := make([]relational.UserNotificationSubscription, 0, len(subscribedUsers))
			for i := range subscribedUsers {
				if subscribedUsers[i].ID == "" {
					db.Logger.Warn(
						context.Background(),
						"Skipping legacy %s subscription row with empty user ID (batch=%d index=%d)",
						legacyLabel,
						batch,
						i,
					)
					continue
				}

				rows = append(rows, relational.UserNotificationSubscription{
					UserID:           subscribedUsers[i].ID,
					NotificationType: notificationType,
					Channels:         []string{notification.DeliveryChannelEmail},
				})
			}

			if len(rows) == 0 {
				return nil
			}

			return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
		}).Error
}

// migrateSSPProfileIDToJoinTable copies the legacy single profile_id FK from
// system_security_plans into the new ssp_profiles join table. Rows that already
// exist (ON CONFLICT DO NOTHING) are skipped, making the migration idempotent.
func migrateSSPProfileIDToJoinTable(db *gorm.DB) error {
	if !db.Migrator().HasTable("ssp_profiles") {
		return nil
	}
	if !db.Migrator().HasColumn(&relational.SystemSecurityPlan{}, "profile_id") {
		return nil
	}
	return db.Exec(`
		INSERT INTO ssp_profiles (system_security_plan_id, profile_id)
		SELECT id, profile_id FROM system_security_plans
		WHERE profile_id IS NOT NULL
		ON CONFLICT DO NOTHING
	`).Error
}

func MigrateDown(db *gorm.DB) error {
	err := db.Migrator().DropTable(
		&relational.Location{},
		&relational.Party{},
		&relational.BackMatterResource{},
		&relational.BackMatter{},
		&relational.Role{},
		&relational.Revision{},
		&relational.Control{},
		&relational.Group{},
		&relational.ResponsibleParty{},
		&relational.Action{},
		&relational.Metadata{},
		&relational.Catalog{},
		&relational.ControlStatementImplementation{},
		&relational.ImplementedRequirementControlImplementation{},
		&relational.ControlImplementationSet{},
		&relational.ComponentDefinition{},
		&relational.Capability{},
		&relational.DefinedComponent{},
		&relational.Diagram{},
		&relational.DataFlow{},
		&relational.NetworkArchitecture{},
		&relational.AuthorizationBoundary{},
		&relational.InformationType{},
		&relational.SystemInformation{},
		&relational.SystemCharacteristics{},
		&relational.AuthorizedPrivilege{},
		&relational.AuthorizationBoundary{},
		&relational.NetworkArchitecture{},
		&relational.DataFlow{},
		&relational.SystemUser{},
		&relational.LeveragedAuthorization{},
		&relational.SystemComponent{},
		&relational.ImplementedComponent{},
		&relational.InventoryItem{},
		&relational.SystemImplementation{},
		&relational.ControlImplementationResponsibility{},
		&relational.ProvidedControlImplementation{},
		&relational.SatisfiedControlImplementationResponsibility{},
		&relational.Export{},
		&relational.InheritedControlImplementation{},
		&relational.ByComponent{},
		&relational.Statement{},
		&relational.ImplementedRequirement{},
		&relational.ControlImplementation{},
		&relational.SystemSecurityPlan{},
		&relational.SSPProfile{},
		"metadata_responsible_parties",
		"party_locations",
		"party_member_of_organisations",
		"responsible_party_parties",
		"action_responsible_parties",
		"capability_control_implementation_sets",
		"defined_components_control_implementation_sets",

		&relational.AssessmentPlan{},
		&relational.LocalDefinitions{},
		&relational.LocalObjective{},
		&relational.Task{},
		&relational.TaskDependency{},
		&relational.AssessmentAsset{},
		&relational.AssessmentPlatform{},
		&relational.UsesComponent{},
		&relational.AssessmentSubject{},
		&relational.SelectSubjectById{},
		&relational.AssociatedActivity{},
		&relational.Activity{},
		&relational.Step{},
		&relational.ReviewedControls{},
		&relational.ControlSelection{},
		&relational.ControlObjectiveSelection{},
		&relational.SelectObjectiveById{},
		"assessment_asset_components",
		"assessment_plan_assessment_subjects",
		"associated_activity_subjects",
		"local_definition_activities",
		"local_definition_components",
		"local_definition_inventory_items",
		"local_definition_objectives",
		"local_definition_users",
		"metadata_parties",
		"metadata_roles",
		"metadata_locations",
		"responsible_role_parties",
		"responsible_roles",
		"task_subjects",
		"task_tasks",
		"uses_component_responsible_parties",
		"result_observations",
		"result_findings",
		"result_risks",
		"control_selection_assessed_controls_included",
		"control_selection_assessed_controls_excluded",
		&relational.Profile{},
		&relational.Import{},
		&relational.Merge{},
		&relational.Modify{},
		&relational.ParameterSetting{},
		&relational.Alteration{},
		&relational.Addition{},
		&relational.SelectControlById{},
		&relational.AssessmentResult{},
		&relational.Activity{},
		&relational.Step{},
		&relational.Task{},
		&relational.AssessedControlsSelectControlById{},
		&relational.Result{},
		&relational.AssessmentLog{},
		&relational.AssessmentLogEntry{},
		"assessed_controls_select_control_by_id_statements",

		&relational.PlanOfActionAndMilestones{},
		&relational.PlanOfActionAndMilestonesLocalDefinitions{},
		&relational.PoamItem{},
		&relational.Risk{},
		&relational.Observation{},
		&relational.Finding{},
		&riskrel.Risk{},
		&riskrel.RiskScore{},
		&riskrel.RiskEvent{},
		&riskrel.RiskReview{},
		&riskrel.RiskEvidenceLink{},
		&riskrel.RiskControlLink{},
		&riskrel.RiskComponentLink{},
		&riskrel.RiskSubjectLink{},
		&riskrel.RiskOwnerAssignment{},
		&riskrel.RiskThreatRef{},
		&riskrel.RiskRemediationTask{},
		&riskrel.RiskRemediationTemplate{},
		&riskrel.AssessmentSubjectLabel{},
		&riskrel.InventoryItemLabel{},
		&riskrel.SystemComponentLabel{},
		&riskrel.ComponentDefinitionLabel{},
		&templaterel.RiskTemplate{},
		&templaterel.RiskTemplateThreatRef{},
		&templaterel.RiskTemplateLabelSchemaField{},
		&templaterel.RemediationTemplate{},
		&templaterel.RemediationTask{},
		&templaterel.AssessmentSubjectIdentity{},
		&templaterel.SystemComponentIdentity{},
		&templaterel.ComponentDefinitionIdentity{},
		&templaterel.SubjectTemplateSelectorLabel{},
		&templaterel.SubjectTemplateLabelSchemaField{},
		&templaterel.SubjectTemplate{},
		"finding_related_observations",
		"finding_related_risks",
		"poam_item_related_observations",
		"poam_item_related_findings",
		"poam_item_related_risks",
		"poam_observations",
		"poam_findings",
		"poam_risks",

		&poamrel.PoamItemFindingLink{},
		&poamrel.PoamItemControlLink{},
		&poamrel.PoamItemEvidenceLink{},
		&poamrel.PoamItemRiskLink{},
		&poamrel.PoamItemMilestone{},
		&poamrel.PoamItem{},

		&relational.AgentAuthEvent{},
		&relational.AgentServiceAccountKey{},
		&relational.Agent{},
		&relational.SlackLinkAttempt{},
		&relational.SlackUserLink{},
		&relational.User{},
		&relational.UserNotificationSubscription{},
		&relational.SystemNotificationDestination{},

		&Heartbeat{},
		&relational.Evidence{},
		"evidence_activities",
		"evidence_components",
		"evidence_inventory_items",
		"evidence_labels",
		"evidence_subjects",
		&relational.Labels{},
		&suggestionrel.DashboardSuggestionEvent{},
		&suggestionrel.DashboardSuggestion{},
		&suggestionrel.DashboardSuggestionRunCell{},
		&suggestionrel.DashboardSuggestionRun{},
		&relational.Filter{},
		"filter_controls",
		"filter_system_components",

		&relational.TermsAndConditions{},
		"terms_and_conditions_parts",

		&relational.Attestation{},
		"attestation_responsible_parties",

		// Implementation Workflows
	)

	// Drop workflow tables separately
	workflowTables := workflows.GetWorkflowTables()
	for _, table := range workflowTables {
		if err := db.Migrator().DropTable(table); err != nil {
			return err
		}
	}

	return err
}
