package oscal

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path"

	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newImportCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import OSCAL data into the system",
		Long:  "This command allows you to import OSCAL data such as catalogs, profiles, and system security plans into the compliance framework configuration service.",
		Run:   importOscal,
	}

	cmd.Flags().StringArrayP("file", "f", []string{}, "File or directory to import")
	cmd.MarkFlagRequired("file")

	return cmd
}

func importOscal(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer zapLogger.Sync() // flushes buffer, if any

	config := config.NewConfig(sugar)

	files, err := cmd.Flags().GetStringArray("file")
	if err != nil {
		panic(err)
	}

	db, err := service.ConnectSQLDb(context.Background(), config, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	for _, f := range files {
		systemFile, err := os.Open(f)
		if err != nil {
			panic(err)
		}

		err = importFile(db, sugar, systemFile)
		if err != nil {
			panic(err)
		}

	}
}

func importFile(db *gorm.DB, sugar *zap.SugaredLogger, f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		panic(err)
	}

	if info.IsDir() {

		files, err := os.ReadDir(f.Name())
		if err != nil {
			return err
		}

		for _, dirFile := range files {
			if dirFile.Name()[0:1] == "." {
				continue
			}

			systemFile, err := os.Open(path.Join(info.Name(), dirFile.Name()))
			if err != nil {
				panic(err)
			}
			defer systemFile.Close()

			err = importFile(db, sugar, systemFile)
			if err != nil {
				panic(err)
			}
		}

		return nil
	}

	sugar.Infow("Importing file", "file", info.Name())

	input := &struct {
		ComponentDefinition       *oscalTypes_1_1_3.ComponentDefinition       `json:"component-definition"`
		Catalog                   *oscalTypes_1_1_3.Catalog                   `json:"catalog"`
		SystemSecurityPlan        *oscalTypes_1_1_3.SystemSecurityPlan        `json:"system-security-plan"`
		AssessmentPlan            *oscalTypes_1_1_3.AssessmentPlan            `json:"assessment-plan"`
		AssessmentResult          *oscalTypes_1_1_3.AssessmentResults         `json:"assessment-results"`
		Profile                   *oscalTypes_1_1_3.Profile                   `json:"profile"`
		PlanOfActionAndMilestones *oscalTypes_1_1_3.PlanOfActionAndMilestones `json:"plan-of-action-and-milestones"`
	}{}

	err = json.NewDecoder(f).Decode(input)
	if err != nil {
		sugar.Error(err)
	}

	if input.Catalog != nil {
		def := &relational.Catalog{}
		def.UnmarshalOscal(*input.Catalog)
		out := db.FirstOrCreate(def)
		if out.Error != nil {
			sugar.Error(out.Error)
		}
		sugar.Infow("Successfully Created Catalog", "title", def.Metadata.Title, "file", f.Name())
		return nil
	}

	if input.ComponentDefinition != nil {
		def := &relational.ComponentDefinition{}
		def.UnmarshalOscal(*input.ComponentDefinition)
		out := db.FirstOrCreate(def)
		if out.Error != nil {
			sugar.Error(out.Error)
		}
		sugar.Infow("Successfully Created Component Definition", "title", def.Metadata.Title, "file", f.Name())
		return nil
	}

	if input.SystemSecurityPlan != nil {
		def := &relational.SystemSecurityPlan{}
		def.UnmarshalOscal(*input.SystemSecurityPlan)
		out := db.FirstOrCreate(def)
		if out.Error != nil {
			sugar.Error(out.Error)
		}
		sugar.Infow("Successfully Created System Security Plan", "title", def.Metadata.Title, "file", f.Name())
		return nil
	}

	if input.AssessmentPlan != nil {
		def := &relational.AssessmentPlan{}
		def.UnmarshalOscal(*input.AssessmentPlan)
		out := db.FirstOrCreate(def)
		if out.Error != nil {
			panic(out.Error)
		}
		sugar.Infow("Successfully Created Assessment Plan", "title", def.Metadata.Title, "file", f.Name())
		return nil
	}

	if input.AssessmentResult != nil {
		def := &relational.AssessmentResult{}
		def.UnmarshalOscal(*input.AssessmentResult)
		out := db.FirstOrCreate(def)
		if out.Error != nil {
			panic(out.Error)
		}
		sugar.Infow("Successfully Created Assessment Result", "title", def.Metadata.Title, "file", f.Name())
		return nil
	}

	if input.Profile != nil {
		def := &relational.Profile{}
		def.UnmarshalOscal(*input.Profile)
		out := db.FirstOrCreate(def)
		if out.Error != nil {
			panic(out.Error)
		}
		sugar.Infow("Successfully Created Profile", "title", def.Metadata.Title, "file", f.Name())
		return nil
	}

	if input.PlanOfActionAndMilestones != nil {
		def := &relational.PlanOfActionAndMilestones{}
		def.UnmarshalOscal(*input.PlanOfActionAndMilestones)

		// Print what we're going to import
		sugar.Infof("Importing POAM with %d risks, %d observations, %d findings",
			len(def.Risks), len(def.Observations), len(def.Findings))

		// Create with polymorphic entities
		out := db.FirstOrCreate(def)
		if out.Error != nil {
			sugar.Errorf("Error creating POAM: %v", out.Error)
			return err
		}
		sugar.Infow("Successfully Created Plan of Action and Milestones", "title", def.Metadata.Title, "file", f.Name())
		return nil
	}

	// Reset the file to the beginning. We'll read it again.
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	output := &map[string]any{}
	decoder := json.NewDecoder(f)
	err = decoder.Decode(output)
	if err != nil {
		sugar.Error(err)
		return err
	}

	for k, _ := range *output {
		sugar.Errorf("Failed to import OSCAL document. `%s` is not yet supported.", k)
	}

	return nil
}
