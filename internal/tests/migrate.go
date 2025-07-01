//go:build integration

package tests

import (
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
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
	return t.db.AutoMigrate(
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
		&relational.User{},
		// POAM entities
		&relational.PlanOfActionAndMilestones{},
		&relational.Observation{},
		&relational.Risk{},
		&relational.Finding{},
		&relational.PoamItem{},

		&service.Heartbeat{},
		&relational.Evidence{},
		&relational.Labels{},
		&relational.SelectSubjectById{},
		&relational.Step{},
	)
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
		&relational.User{},
		// POAM entities
		&relational.PlanOfActionAndMilestones{},
		&relational.Observation{},
		&relational.Risk{},
		&relational.Finding{},
		&relational.PoamItem{},
		"metadata_responsible_parties",
		"party_locations",
		"party_member_of_organisations",
		"responsible_party_parties",
		"action_responsible_parties",
		"capability_control_implementation_sets",
		"defined_components_control_implementation_sets",
		"authorization_boundary_diagrams",
		"network_architecture_diagrams",
		"data_flow_diagrams",
		"back_matter_resources",

		&service.Heartbeat{},
		&relational.Evidence{},
		&relational.Labels{},
		"evidence_labels",
		"evidence_subjects",
		"evidence_activities",
		"evidence_components",

		&relational.SelectSubjectById{},
		&relational.Step{},
	)
}

func (t *TestMigrator) CreateUser() error {
	user := &relational.User{
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
	}
	user.SetPassword("Pa55w0rd")
	return t.db.Create(user).Error
}
