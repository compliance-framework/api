//go:build integration

package tests

import (
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	poamrel "github.com/compliance-framework/api/internal/service/relational/poam"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"gorm.io/gorm"
)

type TestMigrator struct {
	db *gorm.DB
}

func NewTestMigrator(db *gorm.DB) *TestMigrator {
	return &TestMigrator{
		db: db,
	}
}

func (t *TestMigrator) Refresh() error {
	err := t.Down()
	if err != nil {
		return err
	}

	err = t.Up()
	if err != nil {
		return err
	}
	err = t.CreateUser()
	if err != nil {
		return err
	}

	return nil
}

func (t *TestMigrator) Up() error {
	if err := t.db.AutoMigrate(
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
		&relational.AuthorizationBoundary{},
		&relational.NetworkArchitecture{},
		&relational.DataFlow{},
		&relational.Diagram{},

		&relational.AssessmentPlan{},
		&relational.TermsAndConditions{},
		&relational.AssessmentPart{},
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
		&relational.Attestation{},
		&relational.Agent{},
		&relational.AgentServiceAccountKey{},
		&relational.AgentAuthEvent{},
		&relational.SSOUserLink{},
		&relational.SlackLinkAttempt{},
		&relational.SlackUserLink{},
		&relational.User{},
		&relational.UserNotificationSubscription{},
		&relational.SystemNotificationDestination{},

		&service.Heartbeat{},
		&poamrel.PoamItem{},
		&poamrel.PoamItemMilestone{},
		&poamrel.PoamItemRiskLink{},
		&poamrel.PoamItemEvidenceLink{},
		&poamrel.PoamItemControlLink{},
		&poamrel.PoamItemFindingLink{},
		&relational.Evidence{},
		&relational.Labels{},
		&relational.SelectSubjectById{},
		&relational.Filter{},
		&suggestionrel.DashboardSuggestionRun{},
		&suggestionrel.DashboardSuggestionRunCell{},
		&suggestionrel.DashboardSuggestion{},
		&suggestionrel.DashboardSuggestionEvent{},
		&relational.Step{},
	); err != nil {
		return err
	}
	if err := riskrel.EnsureIndexes(t.db); err != nil {
		return err
	}

	// Add unique constraints for idempotent operations (matching production migration)
	if t.db.Name() == "postgres" {
		// Partial unique index for system_components
		if err := t.db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_system_components_unique_impl_defined
			ON system_components (system_implementation_id, defined_component_id)
			WHERE defined_component_id IS NOT NULL
		`).Error; err != nil {
			return err
		}

		// Align join-table control_catalog_id columns to uuid (matching production migration
		// in service.MigrateUpWithConfig) so integration tests exercise the same uuid join path.
		if err := t.db.Exec(`
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

		if err := t.db.Exec(`
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

		if err := t.db.Exec(`
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

		if err := t.db.Exec(`
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

		if err := t.db.Exec(`
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

		if err := t.db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_suggestions_unique_pending
			ON dashboard_suggestions (ssp_id, control_catalog_id, control_id, label_set_hash)
			WHERE status = 'pending'
		`).Error; err != nil {
			return err
		}

		if err := t.db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_suggestions_unique_pending_filter_labels
			ON dashboard_suggestions (ssp_id, control_catalog_id, control_id, proposed_filter_label_set)
			WHERE status = 'pending'
			  AND proposed_filter_label_set IS NOT NULL
			  AND proposed_filter_label_set <> 'null'::jsonb
		`).Error; err != nil {
			return err
		}

		if err := t.db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_suggestion_runs_unique_active
			ON dashboard_suggestion_runs (ssp_id)
			WHERE status IN ('pending', 'running')
		`).Error; err != nil {
			return err
		}
	}

	return nil
}

func (t *TestMigrator) Down() error {
	return t.db.Migrator().DropTable(
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
		"metadata_responsible_parties",
		"party_locations",
		"party_member_of_organisations",
		"responsible_party_parties",
		"action_responsible_parties",
		"capability_control_implementation_sets",
		"defined_components_control_implementation_sets",
		&relational.AssessmentPlan{},
		&relational.TermsAndConditions{},
		&relational.AssessmentPart{},
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
		&poamrel.PoamItemFindingLink{},
		&poamrel.PoamItemControlLink{},
		&poamrel.PoamItemEvidenceLink{},
		&poamrel.PoamItemRiskLink{},
		&poamrel.PoamItemMilestone{},
		&poamrel.PoamItem{},
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

		&relational.AgentAuthEvent{},
		&relational.AgentServiceAccountKey{},
		&relational.Agent{},
		&relational.SSOUserLink{},
		&relational.SlackLinkAttempt{},
		&relational.SlackUserLink{},
		&relational.User{},
		&relational.UserNotificationSubscription{},
		&relational.SystemNotificationDestination{},

		&service.Heartbeat{},
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
	)
}

func (t *TestMigrator) CreateUser() error {
	user := &relational.User{
		Email:     "dummy@example.com",
		FirstName: "Dummy",
		LastName:  "User",
	}
	user.SetPassword("Pa55w0rd")
	return t.db.Create(user).Error
}
