package seed

import (
	"context"
	"fmt"
	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
	"gorm.io/datatypes"
	"gorm.io/gorm/clause"
	"log"
	"sync"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newEvidenceCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Generates evidence",
		Run:   generateEvidence,
	}

	cmd.Flags().IntP("amount", "a", 10, "Amount of evidences")
	cmd.Flags().IntP("beats", "b", 5, "Amount of beats per evidence")

	return cmd
}

func generateEvidence(cmd *cobra.Command, args []string) {
	var err error

	amount := 10
	if cmd.Flags().Changed("amount") {
		amount, err = cmd.Flags().GetInt("amount")
		if err != nil {
			log.Fatal(err)
		}
	}

	beats := 5 // each minute of a day
	if cmd.Flags().Changed("beats") {
		beats, err = cmd.Flags().GetInt("beats")
		if err != nil {
			log.Fatal(err)
		}
	}

	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer zapLogger.Sync() // flushes buffer, if any

	cmdConfig := config.NewConfig(sugar)
	db, err := service.ConnectSQLDb(context.Background(), cmdConfig, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	bar := progressbar.Default(int64(amount * beats))
	defer bar.Close()

	var wg sync.WaitGroup
	for i := range amount {
		wg.Add(1)
		go func() {
			defer wg.Done()

			evidenceId := uuid.New()

			components := []relational.SystemComponent{
				{
					UUIDModel: relational.UUIDModel{
						ID: internal.Pointer(uuid.New()),
					},
					Type:  "component",
					Title: fmt.Sprintf("Some component - %d", i),
				},
				{
					UUIDModel: relational.UUIDModel{
						ID: internal.Pointer(uuid.New()),
					},
					Type:  "component",
					Title: fmt.Sprintf("Some other component - %d", i),
				},
			}
			db.Clauses(clause.OnConflict{DoNothing: true}).Create(&components)

			inventoryItems := []relational.InventoryItem{
				{
					UUIDModel: relational.UUIDModel{
						ID: internal.Pointer(uuid.New()),
					},
					Description: fmt.Sprintf("EC2 Instance - %d", i),
					ImplementedComponents: []relational.ImplementedComponent{
						{ComponentID: *components[0].ID},
						{ComponentID: *components[1].ID},
					},
				},
			}
			db.Clauses(clause.OnConflict{DoNothing: true}).Create(&inventoryItems)

			activities := []relational.Activity{
				{
					Title: internal.Pointer("Activity - 1"),
					Steps: []relational.Step{
						{
							Title: internal.Pointer("Activity - 1 - Step - 1"),
						},
						{
							Title: internal.Pointer("Activity - 1 - Step - 2"),
						},
					},
				},
				{
					Title: internal.Pointer("Activity - 2"),
					Steps: []relational.Step{
						{
							Title: internal.Pointer("Activity - 2 - Step - 1"),
						},
						{
							Title: internal.Pointer("Activity - 2 - Step - 2"),
						},
					},
				},
			}
			db.Clauses(clause.OnConflict{DoNothing: true}).Create(&activities)

			subjects := []relational.AssessmentSubject{
				{
					Type: "component",
					IncludeSubjects: []relational.SelectSubjectById{
						{
							SubjectUUID: *components[0].ID,
						},
					},
				},
				{
					Type: "component",
					IncludeSubjects: []relational.SelectSubjectById{
						{
							SubjectUUID: *components[1].ID,
						},
					},
				},
			}
			db.Clauses(clause.OnConflict{DoNothing: true}).Create(&subjects)

			labels := []relational.Labels{
				{
					Name:  "provider",
					Value: "AWS",
				},
				{
					Name:  "service",
					Value: "EC2",
				},
				{
					Name:  "instance",
					Value: fmt.Sprintf("i-%d", i),
				},
			}
			db.Clauses(clause.OnConflict{DoNothing: true}).Create(&labels)

			evidences := []relational.Evidence{}
			for b := range beats {
				err = bar.Add(1)
				if err != nil {
					log.Fatal(err)
				}

				evidences = append(evidences, relational.Evidence{
					UUID:  evidenceId,
					Title: fmt.Sprintf("Evidence %d", b),
					Start: time.Now().Add(-(time.Duration(b) * time.Minute)),
					End:   time.Now().Add(-(time.Minute + (time.Duration(b) * time.Minute))),
					Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
						Reason: "pass",
						State:  "satisfied",
					}),
					Activities:     activities,
					InventoryItems: inventoryItems,
					Components:     components,
					Subjects:       subjects,
					Labels:         labels,
				})

				if len(evidences) > 500 {
					if err := db.Create(&evidences).Error; err != nil {
						panic(err)
					}
					evidences = []relational.Evidence{}
				}
			}
			if err := db.Create(&evidences).Error; err != nil {
				panic(err)
			}
			evidences = []relational.Evidence{}
		}()
	}
	wg.Wait()
}
