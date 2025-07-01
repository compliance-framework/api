package seed

import (
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
	"log"
	"sync"
	"time"

	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newHeartbeatCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "heartbeats",
		Short: "Generates agent heartbeats",
		Run:   generateHeartbeats,
	}

	cmd.Flags().CountP("amount", "a", "Amount of agents")
	cmd.Flags().CountP("beats", "b", "Amount of beats per agent")

	return cmd
}

func generateHeartbeats(cmd *cobra.Command, args []string) {
	var err error

	amount := 10
	if cmd.Flags().Changed("amount") {
		amount, err = cmd.Flags().GetCount("amount")
		if err != nil {
			log.Fatal(err)
		}
	}

	count := 1440 // each minute of a day
	if cmd.Flags().Changed("beats") {
		count, err = cmd.Flags().GetCount("beats")
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
	db, err := service.ConnectSQLDb(cmdConfig, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	bar := progressbar.Default(int64(amount * count))
	defer bar.Close()

	var wg sync.WaitGroup
	for range amount {
		wg.Add(1)
		agentId := uuid.New()
		go func() {
			defer wg.Done()
			for b := range count {
				err = bar.Add(1)
				if err != nil {
					log.Println(err)
				}
				if err := db.Model(&service.Heartbeat{}).Create(&service.Heartbeat{
					UUID:      agentId,
					CreatedAt: time.Now().Add(time.Duration(b) * time.Minute),
				}).Error; err != nil {
					log.Println(err)
				}
			}
		}()
	}
	wg.Wait()
}
