package main

import (
	"github.com/compliance-framework/configuration-service/internal/adapter/api"
	"github.com/compliance-framework/configuration-service/internal/adapter/store/mongo"
	"github.com/compliance-framework/configuration-service/internal/domain/service"
	"log"
	"os"
	"sync"

	"go.uber.org/zap"
)

func main() {
	var wg sync.WaitGroup

	mongoUri := getEnvironmentVariable("MONGO_URI", "mongodb://mongo:27017")
	//natsUri := getEnvironmentVariable("NATS_URI", "nats://nats:4222")

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := logger.Sugar()

	err = mongo.Connect(mongoUri, "cf")
	if err != nil {
		sugar.Fatalf("error connecting to mongo: %v", err)
	}

	//job := jobs.RuntimeJobManager{Log: sugar, Driver: driver}
	//checkErr(job.Init())
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	job.Run()
	//}()
	//
	//sub := jobs.EventSubscriber{Log: sugar}
	//checkErr(sub.Connect(natsUri))
	//ch := sub.Subscribe("assessment.result")
	//
	//process := jobs.EventProcessor{Log: sugar, Driver: driver}
	//checkErr(process.Init(ch))
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	process.Run()
	//}()
	//
	//pub := jobs.EventPublisher{Log: sugar}
	//checkErr(pub.Connect(natsUri))
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	pub.Run()
	//}()

	server := api.NewServer()
	controlService := service.NewControlService()
	controlHandler := api.NewControlHandler(controlService)
	server.Route("GET", "/controls/:id", controlHandler.GetControl)
	checkErr(server.Start(":8080"))

	wg.Wait()

	err = mongo.Disconnect()
	if err != nil {
		sugar.Fatalf("error disconnecting from mongo: %v", err)
	}
}

func getEnvironmentVariable(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func checkErr(err error) {
	if err != nil {
		log.Fatalf("An error occurred: %v", err)
	}
}
