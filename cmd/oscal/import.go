package oscal

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	importCmd = &cobra.Command{
		Use:   "import",
		Short: "Import OSCAL data into the system",
		Long:  "This command allows you to import OSCAL data such as catalogs, profiles, and system security plans into the compliance framework configuration service.",
		Run:   ImportOscal,
	}
)

func ImportOscal(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer zapLogger.Sync() // flushes buffer, if any

	config := config.NewConfig(sugar)

	db, err := service.ConnectSQLDb(config, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	// Reset the entire database in local
	err = service.MigrateDown(db)
	if err != nil {
		panic(err)
	}

	err = service.MigrateUp(db)
	if err != nil {
		panic(err)
	}

	files := []string{
		"testdata/basic-catalog.json",
		"testdata/example-ap.json",
		"testdata/example-ssp.json",
		"testdata/full_ssp.json",
		"testdata/NIST_SP-800_218_catalog.json",
		"testdata/OWASP_DSOMM_3.28.2.json",
		"testdata/SAMA_CSF_1.0_catalog.json",
		"testdata/SAMA_ITGF_1.0_catalog.json",
		"testdata/sp800-53-component.json",
		"testdata/sp800-53-component-aws.json",
		"testdata/sp800_53_catalog.json",
		"testdata/sp800_53_component_definition_sample.json",
		"testdata/sp800_53_profile.json",
	}

	for _, f := range files {
		jsonFile, err := os.Open(f)
		if err != nil {
			panic(err)
		}

		defer jsonFile.Close()
		input := &struct {
			ComponentDefinition *oscalTypes_1_1_3.ComponentDefinition `json:"component-definition"`
			Catalog             *oscalTypes_1_1_3.Catalog             `json:"catalog"`
			SystemSecurityPlan  *oscalTypes_1_1_3.SystemSecurityPlan  `json:"system-security-plan"`
			AssessmentPlan      *oscalTypes_1_1_3.AssessmentPlan      `json:"assessment-plan"`
			Profile             *oscalTypes_1_1_3.Profile             `json:"profile"`
		}{}

		err = json.NewDecoder(jsonFile).Decode(input)
		if err != nil {
			sugar.Error(err)
		}

		if input.Catalog != nil {
			def := &relational.Catalog{}
			def.UnmarshalOscal(*input.Catalog)
			out := db.Create(def)
			if out.Error != nil {
				sugar.Error(out.Error)
			}
			fmt.Println("Successfully Created Catalog", f)
			continue
		}

		if input.ComponentDefinition != nil {
			def := &relational.ComponentDefinition{}
			def.UnmarshalOscal(*input.ComponentDefinition)
			out := db.Create(def)
			if out.Error != nil {
				sugar.Error(out.Error)
			}
			fmt.Println("Successfully Created ComponentDefinition", f)
			continue
		}

		if input.SystemSecurityPlan != nil {
			def := &relational.SystemSecurityPlan{}
			def.UnmarshalOscal(*input.SystemSecurityPlan)
			out := db.Create(def)
			if out.Error != nil {
				sugar.Error(out.Error)
			}
			fmt.Println("Successfully Created SystemSecurityPlan", f)
			continue
		}

		if input.AssessmentPlan != nil {
			def := &relational.AssessmentPlan{}
			def.UnmarshalOscal(*input.AssessmentPlan)
			out := db.Create(def)
			if out.Error != nil {
				panic(out.Error)
			}
			fmt.Println("Successfully Created Assessment Plan", f)
			continue
		}

		if input.Profile != nil {
			def := &relational.Profile{}
			def.UnmarshalOscal(*input.Profile)
			out := db.Create(def)
			if out.Error != nil {
				panic(out.Error)
			}
			fmt.Println("Successfully Created Profile", f)
			continue
		}

		sugar.Fatal("File content wasn't understood or mapped: ", f)
	}
}
