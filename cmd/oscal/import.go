package oscal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path"

	"github.com/compliance-framework/api/internal/api/handler/oscal"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
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
	failOnError(cmd.MarkFlagRequired("file"))

	return cmd
}

func failOnError(err error) {
	if err != nil {
		panic(err)
	}
}
func importOscal(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer func() {
		_ = zapLogger.Sync() // Flushes buffer, if any. We ignore errors here (that are commonly-seen) as distracting and not of note.
	}()

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

// importResult reports what upsertDocument did with a document.
type importResult struct {
	created bool
	err     error
}

// upsertDocument creates the document when its uuid is new, and otherwise
// updates it from the file contents (FullSaveAssociations upserts every
// nested row by primary key). Re-importing an updated file therefore
// propagates new controls, requirements and statements instead of being
// silently skipped.
//
// Update semantics are additive: struct-based Updates skips zero-value
// fields, so DB-managed columns not represented in OSCAL (e.g. a catalog's
// Active flag) are left untouched, and rows or values removed from the file
// are NOT deleted or cleared.
func upsertDocument[T any](db *gorm.DB, rawID string, def *T) importResult {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return importResult{err: err}
	}

	var existing T
	err = db.Select("id").First(&existing, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return importResult{created: true, err: db.Create(def).Error}
	}
	if err != nil {
		return importResult{err: err}
	}
	return importResult{err: db.Session(&gorm.Session{FullSaveAssociations: true}).Updates(def).Error}
}

func logImport(sugar *zap.SugaredLogger, res importResult, kind, title, file string) {
	if res.err != nil {
		sugar.Errorw("Failed to import "+kind, "title", title, "file", file, "error", res.err)
		return
	}
	action := "Updated"
	if res.created {
		action = "Created"
	}
	sugar.Infow("Successfully "+action+" "+kind, "title", title, "file", file)
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

			// Join against the path the directory was opened with (f.Name()),
			// not its base name (info.Name()), so nested directories resolve.
			systemFile, err := os.Open(path.Join(f.Name(), dirFile.Name()))
			if err != nil {
				panic(err)
			}
			defer func() {
				err := systemFile.Close()
				if err != nil {
					sugar.Error("failed to close system file", "err", err)
				}
			}()

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

	imported := false

	if input.Catalog != nil {
		def := &relational.Catalog{}
		def.UnmarshalOscal(*input.Catalog)
		logImport(sugar, upsertDocument(db, input.Catalog.UUID, def), "Catalog", def.Metadata.Title, f.Name())
		imported = true
	}

	if input.ComponentDefinition != nil {
		def := &relational.ComponentDefinition{}
		def.UnmarshalOscal(*input.ComponentDefinition)
		logImport(sugar, upsertDocument(db, input.ComponentDefinition.UUID, def), "Component Definition", def.Metadata.Title, f.Name())
		imported = true
	}

	if input.SystemSecurityPlan != nil {
		def := &relational.SystemSecurityPlan{}
		def.UnmarshalOscal(*input.SystemSecurityPlan)
		logImport(sugar, upsertDocument(db, input.SystemSecurityPlan.UUID, def), "System Security Plan", def.Metadata.Title, f.Name())
		imported = true
	}

	if input.AssessmentPlan != nil {
		def := &relational.AssessmentPlan{}
		def.UnmarshalOscal(*input.AssessmentPlan)
		logImport(sugar, upsertDocument(db, input.AssessmentPlan.UUID, def), "Assessment Plan", def.Metadata.Title, f.Name())
		imported = true
	}

	if input.AssessmentResult != nil {
		def := &relational.AssessmentResult{}
		def.UnmarshalOscal(*input.AssessmentResult)
		logImport(sugar, upsertDocument(db, input.AssessmentResult.UUID, def), "Assessment Result", def.Metadata.Title, f.Name())
		imported = true
	}

	if input.Profile != nil {
		def := &relational.Profile{}
		def.UnmarshalOscal(*input.Profile)
		logImport(sugar, upsertDocument(db, input.Profile.UUID, def), "Profile", def.Metadata.Title, f.Name())

		// Sync ProfileControl pivot table synchronously so errors can be reported
		_, err := oscal.SyncProfileControls(db, uuid.MustParse(input.Profile.UUID))
		if err != nil {
			sugar.Errorw("Failed to sync profile controls", "error", err)
			return err
		}

		imported = true
	}

	if input.PlanOfActionAndMilestones != nil {
		def := &relational.PlanOfActionAndMilestones{}
		def.UnmarshalOscal(*input.PlanOfActionAndMilestones)

		// Print what we're going to import
		sugar.Infof("Importing POAM with %d risks, %d observations, %d findings",
			len(def.Risks), len(def.Observations), len(def.Findings))

		logImport(sugar, upsertDocument(db, input.PlanOfActionAndMilestones.UUID, def), "Plan of Action and Milestones", def.Metadata.Title, f.Name())
		imported = true
	}

	if imported {
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

	for k := range *output {
		sugar.Errorf("Failed to import OSCAL document. `%s` is not yet supported.", k)
	}

	return nil
}
