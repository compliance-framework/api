package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	poamrel "github.com/compliance-framework/api/internal/service/relational/poam"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
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
		&relational.ControlLink{},
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
		&relational.SSPExportOffering{},
		&relational.SSPExportOfferingItem{},
		&relational.SSPExportOfferingAllowedDownstream{},
		&relational.SSPLeverageLink{},
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
		&riskrel.RiskResponsibilityLink{},
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
		&relational.UserGroup{},
		&relational.UserGroupMembership{},
		&relational.SSOGroupMapping{},
		&relational.CCFRoleAssignment{},
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
		&relational.FilterResponsibility{},
		&suggestionrel.DashboardSuggestionRun{},
		&suggestionrel.DashboardSuggestionRunCell{},
		&suggestionrel.DashboardSuggestion{},
		&suggestionrel.DashboardSuggestionControlResult{},
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
	if err := migrateBackfillCatalogType(db); err != nil {
		return err
	}
	if err := migrateBackfillCatalogActive(db); err != nil {
		return err
	}
	if err := migrateBackfillOfferingItemStatementIDs(db); err != nil {
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

		// Align control_implementation_responsibilities.provided_uuid (historically text,
		// since ControlImplementationResponsibility.ProvidedUuid carries no explicit
		// gorm uuid type tag) with ssp_leverage_links.provided_uuid, which is uuid — the
		// BCH-1339 filter_responsibilities → ssp_leverage_links resolution arm
		// (risk_evidence_worker.go) joins these two columns directly. Same idempotent
		// fix as filter_controls/profile_controls's control_catalog_id above.
		if err := db.Exec(`
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'control_implementation_responsibilities'
			      AND column_name = 'provided_uuid'
			      AND data_type = 'text'
			  ) THEN
			    ALTER TABLE control_implementation_responsibilities
			      ALTER COLUMN provided_uuid TYPE uuid
			      USING NULLIF(provided_uuid, '')::uuid;
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

		// FilterResponsibility.SSPID (BCH-1339) mirrors filters.ssp_id above: it should
		// cascade-delete when its downstream SSP is deleted, same as the association
		// declared in the Go struct (relational.FilterResponsibility.SystemSecurityPlan).
		if err := db.Exec(`
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'filter_responsibilities'
			      AND column_name = 'ssp_id'
			  ) AND NOT EXISTS (
			    SELECT 1 FROM pg_constraint
			    WHERE conname = 'fk_filter_responsibilities_system_security_plan'
			  ) THEN
			    ALTER TABLE filter_responsibilities
			      ADD CONSTRAINT fk_filter_responsibilities_system_security_plan
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
			DO $$
			BEGIN
			  IF EXISTS (
			    SELECT 1 FROM information_schema.columns
			    WHERE table_name = 'dashboard_suggestion_control_results'
			      AND column_name = 'run_id'
			  ) AND NOT EXISTS (
			    SELECT 1 FROM pg_constraint
			    WHERE conname = 'fk_dashboard_suggestion_control_results_run'
			  ) THEN
			    ALTER TABLE dashboard_suggestion_control_results
			      ADD CONSTRAINT fk_dashboard_suggestion_control_results_run
			      FOREIGN KEY (run_id)
			      REFERENCES dashboard_suggestion_runs(id)
			      ON DELETE CASCADE;
			  END IF;
			END $$;
		`).Error; err != nil {
			return err
		}

		if err := db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_suggestion_control_results_unique_run_control
			ON dashboard_suggestion_control_results (run_id, control_catalog_id, control_id)
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

	// Reconcile the role-assignment config file into the persisted ccf_role_assignments table
	// (BCH-1334). With BCH-1333 the table is the PDP's source of truth, so authz-roles.yaml is a
	// boot seed: its user/group grants are upserted as source=config and stale config grants removed,
	// before the server serves traffic. A bad/typo'd file fails fast here (the caller treats a
	// migration error as fatal). Runs whenever authz config is present; MigrateUp(db, nil) skips it.
	if cfg != nil && cfg.Authz != nil {
		if err := authz.ReconcileConfigRoleAssignments(context.Background(), db, cfg.Authz.RoleAssignmentsPath, nil); err != nil {
			return err
		}
	}

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

// migrateBackfillCatalogType ensures every existing catalog row carries a concrete
// catalog_type. AutoMigrate adds the column with a 'standard' default (Postgres
// backfills existing rows on ADD COLUMN), but this keeps the invariant explicit and
// idempotent across drivers, following the established data-migration step pattern.
func migrateBackfillCatalogType(db *gorm.DB) error {
	if !db.Migrator().HasColumn(&relational.Catalog{}, "catalog_type") {
		return nil
	}
	return db.Model(&relational.Catalog{}).
		Where("catalog_type IS NULL OR catalog_type = ''").
		Update("catalog_type", relational.CatalogTypeStandard).Error
}

// migrateBackfillCatalogActive ensures every existing catalog row is marked active.
// AutoMigrate adds the column with a 'true' default (Postgres backfills existing
// rows on ADD COLUMN), but this keeps the invariant explicit and idempotent across
// drivers so catalogs pre-dating the column are never hidden from the lineage roots.
func migrateBackfillCatalogActive(db *gorm.DB) error {
	if !db.Migrator().HasColumn(&relational.Catalog{}, "active") {
		return nil
	}
	return db.Model(&relational.Catalog{}).
		Where("active IS NULL").
		Update("active", true).Error
}

// migrateBackfillOfferingItemStatementIDs normalizes legacy ssp_export_offering_items
// rows written before the statement became the canonical anchor for shared responsibility.
// For each item with a NULL statement_id it walks provided_uuid -> export -> by_component
// and, when that by-component is statement-anchored, copies the parent Statement's
// statement-id onto the item.
//
// A requirement-anchored by-component has no statement to derive, so those rows keep a NULL
// statement_id: they stay readable and deletable, but Subscribe now rejects them with a 422
// rather than silently falling back to requirement-anchoring. The count of both outcomes is
// logged so an operator can see how much legacy data still needs winding down.
//
// The DB column stays nullable on purpose — statement_id is enforced on the write path
// (createExportOfferingItemRequest.validate), not by the schema, so legacy rows survive.
func migrateBackfillOfferingItemStatementIDs(db *gorm.DB) error {
	if !db.Migrator().HasTable(&relational.SSPExportOfferingItem{}) {
		return nil
	}

	var items []relational.SSPExportOfferingItem
	if err := db.Where("statement_id IS NULL").Find(&items).Error; err != nil {
		return fmt.Errorf("failed to load legacy offering items: %w", err)
	}
	if len(items) == 0 {
		return nil
	}

	providedUUIDs := make([]uuid.UUID, 0, len(items))
	seen := make(map[uuid.UUID]bool, len(items))
	for _, item := range items {
		if !seen[item.ProvidedUUID] {
			seen[item.ProvidedUUID] = true
			providedUUIDs = append(providedUUIDs, item.ProvidedUUID)
		}
	}

	var provided []relational.ProvidedControlImplementation
	if err := db.Where("id IN ?", providedUUIDs).Find(&provided).Error; err != nil {
		return fmt.Errorf("failed to load provided control implementations: %w", err)
	}
	exportIDByProvided := make(map[uuid.UUID]uuid.UUID, len(provided))
	exportIDs := make([]uuid.UUID, 0, len(provided))
	for _, p := range provided {
		exportIDByProvided[*p.ID] = p.ExportId
		exportIDs = append(exportIDs, p.ExportId)
	}

	var exports []relational.Export
	if err := db.Where("id IN ?", exportIDs).Find(&exports).Error; err != nil {
		return fmt.Errorf("failed to load exports: %w", err)
	}
	byComponentIDByExport := make(map[uuid.UUID]uuid.UUID, len(exports))
	byComponentIDs := make([]uuid.UUID, 0, len(exports))
	for _, e := range exports {
		byComponentIDByExport[*e.ID] = e.ByComponentId
		byComponentIDs = append(byComponentIDs, e.ByComponentId)
	}

	var byComponents []relational.ByComponent
	if err := db.Where("id IN ?", byComponentIDs).Find(&byComponents).Error; err != nil {
		return fmt.Errorf("failed to load by-components: %w", err)
	}
	statementIDByComponent := make(map[uuid.UUID]uuid.UUID, len(byComponents))
	statementRowIDs := make([]uuid.UUID, 0, len(byComponents))
	for _, bc := range byComponents {
		if bc.ParentType == nil || *bc.ParentType != "statements" || bc.ParentID == nil {
			continue
		}
		statementIDByComponent[*bc.ID] = *bc.ParentID
		statementRowIDs = append(statementRowIDs, *bc.ParentID)
	}

	var statements []relational.Statement
	if len(statementRowIDs) > 0 {
		if err := db.Where("id IN ?", statementRowIDs).Find(&statements).Error; err != nil {
			return fmt.Errorf("failed to load statements: %w", err)
		}
	}
	statementIDByRow := make(map[uuid.UUID]string, len(statements))
	for _, s := range statements {
		statementIDByRow[*s.ID] = s.StatementId
	}

	backfilled, undeterminable := 0, 0
	for _, item := range items {
		exportID, ok := exportIDByProvided[item.ProvidedUUID]
		if !ok {
			undeterminable++
			continue
		}
		byComponentID, ok := byComponentIDByExport[exportID]
		if !ok {
			undeterminable++
			continue
		}
		statementRowID, ok := statementIDByComponent[byComponentID]
		if !ok {
			undeterminable++
			continue
		}
		statementID, ok := statementIDByRow[statementRowID]
		if !ok || statementID == "" {
			undeterminable++
			continue
		}

		if err := db.Model(&relational.SSPExportOfferingItem{}).
			Where("id = ?", item.ID).
			Update("statement_id", statementID).Error; err != nil {
			return fmt.Errorf("failed to backfill statement_id on offering item %s: %w", item.ID, err)
		}
		backfilled++
	}

	db.Logger.Info(
		context.Background(),
		"Backfilled statement_id on %d legacy export offering item(s); %d could not be derived (requirement-anchored or dangling provided-uuid) and remain NULL",
		backfilled,
		undeterminable,
	)
	return nil
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
		&relational.ControlLink{},
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
		&relational.SSPLeverageLink{},
		&relational.SSPExportOfferingAllowedDownstream{},
		&relational.SSPExportOfferingItem{},
		&relational.SSPExportOffering{},
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
		&riskrel.RiskResponsibilityLink{},
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
		&relational.CCFRoleAssignment{},
		&relational.SSOGroupMapping{},
		&relational.UserGroupMembership{},
		&relational.UserGroup{},
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
		&suggestionrel.DashboardSuggestionControlResult{},
		&suggestionrel.DashboardSuggestion{},
		&suggestionrel.DashboardSuggestionRunCell{},
		&suggestionrel.DashboardSuggestionRun{},
		&relational.FilterResponsibility{},
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
