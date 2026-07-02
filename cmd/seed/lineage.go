package seed

import (
	"context"
	"log"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Fixed ids keep the seed idempotent: re-running never duplicates the demo catalogs.
var (
	demoPolicyCatalogID    = uuid.MustParse("aaaa0000-0000-4000-8000-000000000001")
	demoProcedureCatalogID = uuid.MustParse("aaaa0000-0000-4000-8000-000000000002")
)

func newLineageCMD() *cobra.Command {
	return &cobra.Command{
		Use:   "lineage",
		Short: "Seeds demo Policy/Procedure catalogs and control links for the Compliance Lineage PoC",
		Run:   seedLineage,
	}
}

func seedLineage(_ *cobra.Command, _ []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer func() { _ = zapLogger.Sync() }()

	cmdConfig := config.NewConfig(sugar)
	db, err := service.ConnectSQLDb(context.Background(), cmdConfig, sugar)
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Pick the standard catalog local-dev loads: the first standard-type catalog
	// that has controls to anchor the demo policies to.
	standardCatID, standardControls, err := firstStandardCatalogWithControls(db)
	if err != nil {
		log.Fatalf("failed to locate a standard catalog with controls: %v", err)
	}
	if len(standardControls) < 2 {
		log.Fatalf("standard catalog %s has fewer than 2 controls; cannot build a meaningful demo", standardCatID)
	}
	sugar.Infow("seeding lineage against standard catalog", "catalogId", standardCatID, "controls", len(standardControls))

	now := time.Now().UTC()

	// 1) Policy catalog with three policy controls.
	policyCatalog := demoCatalog(demoPolicyCatalogID, relational.CatalogTypePolicy, "Access Control Policy", now, []demoControl{
		{ID: "pol-ac", Title: "Access Control Policy Statement"},
		{ID: "pol-ac-accounts", Title: "Account Management Policy"},
		{ID: "pol-ac-least-priv", Title: "Least Privilege Policy"},
	})
	// 2) Procedure catalog with two procedure controls.
	procedureCatalog := demoCatalog(demoProcedureCatalogID, relational.CatalogTypeProcedure, "Access Control Procedures", now, []demoControl{
		{ID: "proc-ac-onboard", Title: "Account Onboarding Procedure"},
		{ID: "proc-ac-review", Title: "Access Review Procedure"},
	})

	if err := createCatalogIfAbsent(db, &policyCatalog); err != nil {
		log.Fatalf("failed to create policy catalog: %v", err)
	}
	if err := createCatalogIfAbsent(db, &procedureCatalog); err != nil {
		log.Fatalf("failed to create procedure catalog: %v", err)
	}

	polAC := relational.ControlRef{CatalogID: demoPolicyCatalogID, ControlID: "pol-ac"}
	polAccounts := relational.ControlRef{CatalogID: demoPolicyCatalogID, ControlID: "pol-ac-accounts"}
	procOnboard := relational.ControlRef{CatalogID: demoProcedureCatalogID, ControlID: "proc-ac-onboard"}

	links := []relational.ControlLink{
		// Policy controls implement a couple of standard controls (policy -> standard).
		implementsEdge(polAC, standardControls[0]),
		implementsEdge(polAccounts, standardControls[1]),
		// A procedure documents a policy control (procedure -> policy).
		documentsEdge(procOnboard, polAC),
	}

	// Operational controls implement the policy controls (operational -> policy), so
	// evidence/risk on those standard controls rolls UP into the policy. Prefer a
	// control that already carries an open risk so at least one policy shows heat.
	if riskyControl, ok := controlWithOpenRisk(db); ok {
		links = append(links, implementsEdge(riskyControl, polAC))
		sugar.Infow("linked an open-risk operational control to a policy for demo heat", "control", riskyControl)
	}
	// Add a second operational implementer from the standard catalog for structure.
	if len(standardControls) >= 3 {
		links = append(links, implementsEdge(standardControls[2], polAccounts))
	}

	res := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&links)
	if res.Error != nil {
		log.Fatalf("failed to create control links: %v", res.Error)
	}
	sugar.Infow("lineage seed complete", "linksSubmitted", len(links), "linksCreated", res.RowsAffected)
}

type demoControl struct {
	ID    string
	Title string
}

func demoCatalog(id uuid.UUID, catalogType, title string, now time.Time, controls []demoControl) relational.Catalog {
	relControls := make([]relational.Control, 0, len(controls))
	for _, c := range controls {
		relControls = append(relControls, relational.Control{
			CatalogID: id,
			ID:        c.ID,
			Title:     c.Title,
		})
	}
	return relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &id},
		CatalogType: catalogType,
		Metadata: relational.Metadata{
			Title:        title,
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: &now,
		},
		Controls: relControls,
	}
}

func createCatalogIfAbsent(db *gorm.DB, catalog *relational.Catalog) error {
	var count int64
	if err := db.Model(&relational.Catalog{}).Where("id = ?", catalog.ID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return db.Create(catalog).Error
}

func firstStandardCatalogWithControls(db *gorm.DB) (uuid.UUID, []relational.ControlRef, error) {
	var catalogs []relational.Catalog
	if err := db.
		Where("catalog_type = ? OR catalog_type IS NULL OR catalog_type = ''", relational.CatalogTypeStandard).
		Preload("Controls").
		Order("id").
		Find(&catalogs).Error; err != nil {
		return uuid.Nil, nil, err
	}
	for _, cat := range catalogs {
		if cat.ID == nil || len(cat.Controls) == 0 {
			continue
		}
		// Skip the demo catalogs themselves.
		if *cat.ID == demoPolicyCatalogID || *cat.ID == demoProcedureCatalogID {
			continue
		}
		refs := make([]relational.ControlRef, 0, len(cat.Controls))
		for _, c := range cat.Controls {
			refs = append(refs, relational.ControlRef{CatalogID: *cat.ID, ControlID: c.ID})
		}
		return *cat.ID, refs, nil
	}
	return uuid.Nil, nil, gorm.ErrRecordNotFound
}

// controlWithOpenRisk returns a control that has an open (heat-bearing) risk linked,
// so the demo policy it implements shows a non-zero risk score sum.
func controlWithOpenRisk(db *gorm.DB) (relational.ControlRef, bool) {
	var row struct {
		CatalogID uuid.UUID `gorm:"column:catalog_id"`
		ControlID string    `gorm:"column:control_id"`
	}
	err := db.
		Table("risk_control_links rcl").
		Select("rcl.catalog_id, rcl.control_id").
		Joins("JOIN risk_register_risks r ON r.id = rcl.risk_id").
		Where("r.status IN ?", []string{"open", "investigating", "mitigating-planned"}).
		Limit(1).
		Scan(&row).Error
	if err != nil || row.ControlID == "" {
		return relational.ControlRef{}, false
	}
	return relational.ControlRef{CatalogID: row.CatalogID, ControlID: row.ControlID}, true
}

func implementsEdge(source, target relational.ControlRef) relational.ControlLink {
	return relational.ControlLink{
		SourceCatalogID:  source.CatalogID,
		SourceControlID:  source.ControlID,
		TargetCatalogID:  target.CatalogID,
		TargetControlID:  target.ControlID,
		RelationshipType: relational.RelationshipImplements,
	}
}

func documentsEdge(source, target relational.ControlRef) relational.ControlLink {
	return relational.ControlLink{
		SourceCatalogID:  source.CatalogID,
		SourceControlID:  source.ControlID,
		TargetCatalogID:  target.CatalogID,
		TargetControlID:  target.ControlID,
		RelationshipType: relational.RelationshipDocuments,
	}
}
