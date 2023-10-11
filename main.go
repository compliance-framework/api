package main

import (
	"log"
	"os"
	"sync"

	"github.com/compliance-framework/configuration-service/internal/jobs"
	"github.com/compliance-framework/configuration-service/internal/server"
	"github.com/compliance-framework/configuration-service/internal/stores/mongo"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func main() {
	var wg sync.WaitGroup

	mongoUri := getEnv("MONGO_URI", "mongodb://mongo:27017")
	natsUri := getEnv("NATS_URI", "nats://nats:4222")

	driver := &mongo.MongoDriver{Url: mongoUri, Database: "cf"}
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := logger.Sugar()
	e := echo.New()
	e.Use(middleware.Logger())

	job := jobs.RuntimeJobManager{Log: sugar, Driver: driver}
	checkErr(job.Init())
	wg.Add(1)
	go func() {
		defer wg.Done()
		job.Run()
	}()

	sub := jobs.SubscribeJob{Log: sugar}
	checkErr(sub.Connect(natsUri))
	ch := sub.Subscribe("assessment.result")

	process := jobs.ProcessJob{Log: sugar, Driver: driver}
	checkErr(process.Init(ch))
	wg.Add(1)
	go func() {
		defer wg.Done()
		process.Run()
	}()

	pub := jobs.PublishJob{Log: sugar}
	checkErr(pub.Connect(natsUri))
	wg.Add(1)
	go func() {
		defer wg.Done()
		pub.Run()
	}()

	sv := server.Server{Driver: driver}
	checkErr(sv.RegisterOSCAL(e))
	checkErr(sv.RegisterRuntime(e))
	checkErr(sv.RegisterProcess(e))

	checkErr(e.Start(":8080"))

	wg.Wait()
}

func getEnv(key, fallback string) string {
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
