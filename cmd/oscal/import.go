package oscal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	var errs error
	for _, f := range files {
		systemFile, err := os.Open(f)
		if err != nil {
			errs = errors.Join(errs, err)
			sugar.Errorw("Failed to open import path", "path", f, "error", err)
			continue
		}

		if err := importFile(db, sugar, systemFile); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		sugar.Fatalw("Import finished with errors", "error", errs)
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
	reuseSingletonAssociations(db, id, def)
	return importResult{err: db.Session(&gorm.Session{FullSaveAssociations: true}).Updates(def).Error}
}

// reuseSingletonAssociations points has-one association rows that carry no
// stable OSCAL identifier of their own (metadata, back-matter — their ids are
// DB-generated) at the existing rows for this document, so an update modifies
// them in place. Without this, every re-import would insert a duplicate
// metadata/back-matter row alongside the old one.
func reuseSingletonAssociations(db *gorm.DB, parentID uuid.UUID, def any) {
	reuseMetadata := func(parentType string, meta *relational.Metadata) {
		var existing relational.Metadata
		if err := db.Select("id").
			First(&existing, "parent_id = ? AND parent_type = ?", parentID.String(), parentType).
			Error; err == nil {
			meta.ID = existing.ID
		}
	}
	reuseBackMatter := func(parentType string, bm *relational.BackMatter) {
		if bm == nil {
			return
		}
		var existing relational.BackMatter
		if err := db.Select("id").
			First(&existing, "parent_id = ? AND parent_type = ?", parentID.String(), parentType).
			Error; err == nil {
			bm.ID = existing.ID
		}
	}

	switch d := def.(type) {
	case *relational.Catalog:
		reuseMetadata("catalogs", &d.Metadata)
		reuseBackMatter("catalogs", d.BackMatter)
	case *relational.ComponentDefinition:
		reuseMetadata("component_definitions", &d.Metadata)
		reuseBackMatter("component_definitions", &d.BackMatter)
	case *relational.SystemSecurityPlan:
		reuseMetadata("system_security_plans", &d.Metadata)
		reuseBackMatter("system_security_plans", d.BackMatter)
	case *relational.AssessmentPlan:
		reuseMetadata("assessment_plans", &d.Metadata)
		reuseBackMatter("assessment_plans", d.BackMatter)
	case *relational.AssessmentResult:
		reuseMetadata("assessment_results", &d.Metadata)
		reuseBackMatter("assessment_results", d.BackMatter)
	case *relational.Profile:
		reuseMetadata("profiles", &d.Metadata)
		reuseBackMatter("profiles", d.BackMatter)
	case *relational.PlanOfActionAndMilestones:
		reuseMetadata("plan_of_action_and_milestones", &d.Metadata)
		reuseBackMatter("plan_of_action_and_milestones", &d.BackMatter)
	}
}

// logImport reports the result and returns the error (if any) so callers can
// propagate it into the process exit status.
func logImport(sugar *zap.SugaredLogger, res importResult, kind, title, file string) error {
	if res.err != nil {
		sugar.Errorw("Failed to import "+kind, "title", title, "file", file, "error", res.err)
		return res.err
	}
	action := "Updated"
	if res.created {
		action = "Created"
	}
	sugar.Infow("Successfully "+action+" "+kind, "title", title, "file", file)
	return nil
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

		// Import every entry even when one fails, and report the failures
		// together so a bad file surfaces in the exit status without
		// aborting the rest of the directory.
		var errs error
		for _, dirFile := range files {
			if dirFile.Name()[0:1] == "." {
				continue
			}

			// Join against the path the directory was opened with (f.Name()),
			// not its base name (info.Name()), so nested directories resolve.
			systemFile, err := os.Open(path.Join(f.Name(), dirFile.Name()))
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			defer func() {
				err := systemFile.Close()
				if err != nil {
					sugar.Error("failed to close system file", "err", err)
				}
			}()

			if err := importFile(db, sugar, systemFile); err != nil {
				errs = errors.Join(errs, err)
			}
		}

		return errs
	}

	return importDocuments(db, sugar, f)
}

// importDocuments imports the OSCAL documents in a single file. A panic while
// unmarshalling or persisting (e.g. a malformed uuid in the file — the
// relational layer uses uuid.MustParse) is converted into an error so one bad
// file fails the import's exit status without aborting the rest of the batch.
func importDocuments(db *gorm.DB, sugar *zap.SugaredLogger, f *os.File) (errs error) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("importing %s panicked: %v", f.Name(), r)
			sugar.Errorw("Failed to import file", "file", f.Name(), "error", err)
			errs = errors.Join(errs, err)
		}
	}()

	sugar.Infow("Importing file", "file", f.Name())

	input := &struct {
		ComponentDefinition       *oscalTypes_1_1_3.ComponentDefinition       `json:"component-definition"`
		Catalog                   *oscalTypes_1_1_3.Catalog                   `json:"catalog"`
		SystemSecurityPlan        *oscalTypes_1_1_3.SystemSecurityPlan        `json:"system-security-plan"`
		AssessmentPlan            *oscalTypes_1_1_3.AssessmentPlan            `json:"assessment-plan"`
		AssessmentResult          *oscalTypes_1_1_3.AssessmentResults         `json:"assessment-results"`
		Profile                   *oscalTypes_1_1_3.Profile                   `json:"profile"`
		PlanOfActionAndMilestones *oscalTypes_1_1_3.PlanOfActionAndMilestones `json:"plan-of-action-and-milestones"`
	}{}

	if err := json.NewDecoder(f).Decode(input); err != nil {
		sugar.Error(err)
	}

	imported := false

	if input.Catalog != nil {
		def := &relational.Catalog{}
		def.UnmarshalOscal(*input.Catalog)
		errs = errors.Join(errs, logImport(sugar, upsertDocument(db, input.Catalog.UUID, def), "Catalog", def.Metadata.Title, f.Name()))
		imported = true
	}

	if input.ComponentDefinition != nil {
		def := &relational.ComponentDefinition{}
		def.UnmarshalOscal(*input.ComponentDefinition)
		errs = errors.Join(errs, logImport(sugar, upsertDocument(db, input.ComponentDefinition.UUID, def), "Component Definition", def.Metadata.Title, f.Name()))
		imported = true
	}

	if input.SystemSecurityPlan != nil {
		def := &relational.SystemSecurityPlan{}
		def.UnmarshalOscal(*input.SystemSecurityPlan)
		errs = errors.Join(errs, logImport(sugar, upsertDocument(db, input.SystemSecurityPlan.UUID, def), "System Security Plan", def.Metadata.Title, f.Name()))
		imported = true
	}

	if input.AssessmentPlan != nil {
		def := &relational.AssessmentPlan{}
		def.UnmarshalOscal(*input.AssessmentPlan)
		errs = errors.Join(errs, logImport(sugar, upsertDocument(db, input.AssessmentPlan.UUID, def), "Assessment Plan", def.Metadata.Title, f.Name()))
		imported = true
	}

	if input.AssessmentResult != nil {
		def := &relational.AssessmentResult{}
		def.UnmarshalOscal(*input.AssessmentResult)
		errs = errors.Join(errs, logImport(sugar, upsertDocument(db, input.AssessmentResult.UUID, def), "Assessment Result", def.Metadata.Title, f.Name()))
		imported = true
	}

	if input.Profile != nil {
		def := &relational.Profile{}
		def.UnmarshalOscal(*input.Profile)
		errs = errors.Join(errs, logImport(sugar, upsertDocument(db, input.Profile.UUID, def), "Profile", def.Metadata.Title, f.Name()))

		// Sync ProfileControl pivot table synchronously so errors can be reported
		if _, err := oscal.SyncProfileControls(db, uuid.MustParse(input.Profile.UUID)); err != nil {
			sugar.Errorw("Failed to sync profile controls", "error", err)
			errs = errors.Join(errs, err)
		}

		imported = true
	}

	if input.PlanOfActionAndMilestones != nil {
		def := &relational.PlanOfActionAndMilestones{}
		def.UnmarshalOscal(*input.PlanOfActionAndMilestones)

		// Print what we're going to import
		sugar.Infof("Importing POAM with %d risks, %d observations, %d findings",
			len(def.Risks), len(def.Observations), len(def.Findings))

		errs = errors.Join(errs, logImport(sugar, upsertDocument(db, input.PlanOfActionAndMilestones.UUID, def), "Plan of Action and Milestones", def.Metadata.Title, f.Name()))
		imported = true
	}

	if imported {
		return errs
	}

	// Reset the file to the beginning. We'll read it again.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	output := &map[string]any{}
	if err := json.NewDecoder(f).Decode(output); err != nil {
		sugar.Error(err)
		return err
	}

	for k := range *output {
		sugar.Errorf("Failed to import OSCAL document. `%s` is not yet supported.", k)
	}

	return nil
}
