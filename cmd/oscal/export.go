package oscal

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newExportCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export OSCAL objects from the system",
		Long:  "This command allows you to export OSCAL objects (SSP, AP, Catalog, Profile) from the compliance framework configuration service to a JSON file.",
		Run:   exportOscal,
	}

	cmd.Flags().StringP("output", "o", "oscal_export.json", "Output file for exported objects")
	cmd.Flags().StringP("type", "t", "", "Type of OSCAL object to export (ssp, ap, catalog, profile)")
	cmd.MarkFlagRequired("output")
	cmd.MarkFlagRequired("type")

	return cmd
}

func exportOscal(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer zapLogger.Sync() // flushes buffer, if any

	config := config.NewConfig(sugar)

	outputFile, err := cmd.Flags().GetString("output")
	if err != nil {
		panic(err)
	}

	exportType, err := cmd.Flags().GetString("type")
	if err != nil {
		panic(err)
	}

	db, err := service.ConnectSQLDb(context.Background(), config, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	file, err := os.Create(outputFile)
	if err != nil {
		sugar.Fatalf("failed to create output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	switch exportType {
	case "ssp":
		if err := exportSSP(db, encoder); err != nil {
			sugar.Fatalf("failed to export SSP: %v", err)
		}
	case "ap":
		if err := exportAP(db, encoder); err != nil {
			sugar.Fatalf("failed to export AP: %v", err)
		}
	case "catalog":
		if err := exportCatalog(db, encoder); err != nil {
			sugar.Fatalf("failed to export Catalog: %v", err)
		}
	case "profile":
		if err := exportProfile(db, encoder); err != nil {
			sugar.Fatalf("failed to export Profile: %v", err)
		}
	default:
		sugar.Fatalf("Unknown export type: %s. Valid types are: ssp, ap, catalog, profile", exportType)
	}

	sugar.Infof("Successfully exported %s to %s", exportType, outputFile)
}

func exportSSP(db *gorm.DB, encoder *json.Encoder) error {
	var ssps []relational.SystemSecurityPlan
	if err := db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Metadata.Roles").
		Preload("Metadata.Parties").
		Preload("Metadata.Parties.Locations").
		Preload("Metadata.Parties.MemberOfOrganizations").
		Preload("Metadata.ResponsibleParties").
		Preload("Metadata.ResponsibleParties.Parties").
		Preload("Metadata.Locations").
		Preload("Metadata.Actions").
		Preload("Metadata.Actions.ResponsibleParties").
		Preload("Metadata.Actions.ResponsibleParties.Parties").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Preload("ControlImplementation").
		Preload("ControlImplementation.ImplementedRequirements").
		Preload("ControlImplementation.ImplementedRequirements.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Provided").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Provided.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Provided.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Responsibilities").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Responsibilities.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Export.Responsibilities.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Inherited").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Inherited.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Inherited.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Satisfied").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Satisfied.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents.Satisfied.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Provided").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Provided.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Provided.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Responsibilities").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Responsibilities.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Export.Responsibilities.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited.ResponsibleRoles.Parties").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied.ResponsibleRoles").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied.ResponsibleRoles.Parties").
		Preload("SystemCharacteristics").
		Preload("SystemCharacteristics.AuthorizationBoundary").
		Preload("SystemCharacteristics.AuthorizationBoundary.Diagrams").
		Preload("SystemCharacteristics.NetworkArchitecture").
		Preload("SystemCharacteristics.NetworkArchitecture.Diagrams").
		Preload("SystemCharacteristics.DataFlow").
		Preload("SystemCharacteristics.DataFlow.Diagrams").
		Preload("SystemImplementation").
		Preload("SystemImplementation.Users").
		Preload("SystemImplementation.Users.AuthorizedPrivileges").
		Preload("SystemImplementation.LeveragedAuthorizations").
		Preload("SystemImplementation.Components").
		Preload("SystemImplementation.Components.ResponsibleRoles").
		Preload("SystemImplementation.Components.ResponsibleRoles.Parties").
		Preload("SystemImplementation.InventoryItems").
		Preload("SystemImplementation.InventoryItems.ImplementedComponents").
		Find(&ssps).Error; err != nil {
		return err
	}

	oscalList := make([]any, len(ssps))
	for i, ssp := range ssps {
		oscalList[i] = ssp.MarshalOscal()
	}
	return encoder.Encode(oscalList)
}

func exportAP(db *gorm.DB, encoder *json.Encoder) error {
	var plans []relational.AssessmentPlan
	if err := db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Tasks").
		Preload("Tasks.Dependencies").
		Preload("Tasks.Tasks").
		Preload("Tasks.AssociatedActivities").
		Preload("Tasks.AssociatedActivities.Subjects").
		Preload("Tasks.AssociatedActivities.Activity").
		Preload("Tasks.Subjects").
		Preload("Tasks.ResponsibleRole").
		Preload("AssessmentAssets").
		Preload("AssessmentSubjects").
		Preload("LocalDefinitions").
		Preload("TermsAndConditions").
		Preload("BackMatter").
		Find(&plans).Error; err != nil {
		return err
	}

	oscalList := make([]any, len(plans))
	for i, plan := range plans {
		oscalList[i] = plan.MarshalOscal()
	}
	return encoder.Encode(oscalList)
}

func exportCatalog(db *gorm.DB, encoder *json.Encoder) error {
	var catalogs []relational.Catalog
	if err := db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Metadata.Parties").
		Preload("Metadata.ResponsibleParties").
		Preload("Metadata.ResponsibleParties.Parties").
		Preload("Controls").
		Preload("Controls.Controls").
		Preload("Groups").
		Preload("Groups.Controls").
		Preload("Groups.Controls.Controls").
		Preload("Groups.Groups").
		Preload("Groups.Groups.Controls").
		Preload("Groups.Groups.Controls.Controls").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Find(&catalogs).Error; err != nil {
		return err
	}

	oscalList := make([]any, len(catalogs))
	for i, catalog := range catalogs {
		oscalList[i] = catalog.MarshalOscal()
	}
	return encoder.Encode(oscalList)
}

func exportProfile(db *gorm.DB, encoder *json.Encoder) error {
	var profiles []relational.Profile
	if err := db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Imports").
		Preload("Imports.IncludeControls").
		Preload("Imports.ExcludeControls").
		Preload("Merge").
		Preload("Modify").
		Preload("Modify.SetParameters").
		Preload("Modify.Alters").
		Preload("Modify.Alters.Adds").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Find(&profiles).Error; err != nil {
		return err
	}

	oscalList := make([]any, len(profiles))
	for i, profile := range profiles {
		oscalList[i] = profile.MarshalOscal()
	}
	return encoder.Encode(oscalList)
}
