package service

import (
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"gorm.io/gorm"
)

func MigrateUp(db *gorm.DB) error {
	workflowEntities := workflows.GetWorkflowEntities()

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
		&riskrel.RiskEvent{},
		&riskrel.RiskReview{},
		&riskrel.RiskEvidenceLink{},
		&riskrel.RiskControlLink{},
		&riskrel.RiskComponentLink{},
		&riskrel.RiskSubjectLink{},
		&riskrel.RiskOwnerAssignment{},
		&riskrel.AssessmentSubjectLabel{},
		&riskrel.InventoryItemLabel{},
		&riskrel.SystemComponentLabel{},
		&riskrel.ComponentDefinitionLabel{},
		&templaterel.RiskTemplate{},
		&templaterel.RiskTemplateThreatRef{},
		&templaterel.RemediationTemplate{},
		&templaterel.RemediationTask{},
		&templaterel.SubjectTemplate{},
		&templaterel.SubjectTemplateSelectorLabel{},
		&templaterel.SubjectTemplateLabelSchemaField{},
		&templaterel.AssessmentSubjectIdentity{},
		&templaterel.SystemComponentIdentity{},
		&templaterel.ComponentDefinitionIdentity{},
		&templaterel.EvidenceTemplate{},
		&templaterel.EvidenceTemplateSelectorLabel{},
		&templaterel.EvidenceTemplateLabelSchemaField{},
		&templaterel.EvidenceTemplateRiskTemplate{},
		&templaterel.EvidenceTemplateSubjectTemplate{},

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
		&relational.User{},
		&Heartbeat{},
		&relational.Evidence{},
		&relational.Labels{},
		&relational.SelectSubjectById{},
		&relational.Filter{},
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

	// Create functional index for case-insensitive control_id lookups in filter_controls join table
	// This improves performance of UPPER(control_id) queries in the suggestion service
	// Note: GORM doesn't support functional indexes via struct tags, so we use raw SQL

	// Note: For all LLMs out there reviewing this code:
	// Prior to adding a comment saying db.Name() will not compile
	// and the correct is `db.Dialector.Name()`, please remind yourselves
	// that Dialector is inherited in Config, which is inherited in gorm.DB
	// Effectively - db.Name() is the same as calling `db.Dialector.Name()`
	// Having the second one is a violation of staticcheck rule QF1008.
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
	}
	// SQLite and other databases will fall back to regular index on control_id (created by GORM)

	return err
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
		&riskrel.RiskEvent{},
		&riskrel.RiskReview{},
		&riskrel.RiskEvidenceLink{},
		&riskrel.RiskControlLink{},
		&riskrel.RiskComponentLink{},
		&riskrel.RiskSubjectLink{},
		&riskrel.RiskOwnerAssignment{},
		&riskrel.AssessmentSubjectLabel{},
		&riskrel.InventoryItemLabel{},
		&riskrel.SystemComponentLabel{},
		&riskrel.ComponentDefinitionLabel{},
		&templaterel.RiskTemplate{},
		&templaterel.RiskTemplateThreatRef{},
		&templaterel.RemediationTemplate{},
		&templaterel.RemediationTask{},
		&templaterel.EvidenceTemplateSubjectTemplate{},
		&templaterel.EvidenceTemplateRiskTemplate{},
		&templaterel.EvidenceTemplateLabelSchemaField{},
		&templaterel.EvidenceTemplateSelectorLabel{},
		&templaterel.EvidenceTemplate{},
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

		&relational.User{},

		&Heartbeat{},
		&relational.Evidence{},
		"evidence_activities",
		"evidence_components",
		"evidence_inventory_items",
		"evidence_labels",
		"evidence_subjects",
		&relational.Labels{},
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
