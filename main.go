package main

import (
	"os"

	"github.com/compliance-framework/configuration-service/internal/jobs"
	_ "github.com/compliance-framework/configuration-service/internal/models"
	"github.com/compliance-framework/configuration-service/internal/server"
	_ "github.com/compliance-framework/configuration-service/internal/stores"
	"github.com/compliance-framework/configuration-service/internal/stores/mongo"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func main() {
	//driver := &file.FileDriver{Path: "."}
	mongoUri := os.Getenv("MONGO_URI")
	if mongoUri == "" {
		mongoUri = "mongodb://mongo:27017"
	}
	natsUri := os.Getenv("NATS_URI")
	if natsUri == "" {
		natsUri = "nats://nats:4222"
	}
	driver := &mongo.MongoDriver{Url: mongoUri, Database: "cf"}
	e := echo.New()
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	sugar := logger.Sugar()
	e.Use(middleware.Logger())
	job := jobs.RuntimeJobCreator{Log: sugar, Driver: driver}
	err = job.Init()
	if err != nil {
		panic(err)
	}
	go job.Run()
	sub := jobs.SubscribeJob{Log: sugar}
	err = sub.Connect(natsUri)
	if err != nil {
		panic(err)
	}
	ch := sub.Subscribe("assessment.result")
	process := jobs.ProcessJob{Log: sugar, Driver: driver}
	err = process.Init(ch)
	if err != nil {
		panic(err)
	}
	go process.Run()
	pub := jobs.PublishJob{Log: sugar}
	err = pub.Connect(natsUri)
	if err != nil {
		panic(err)
	}
	go pub.Run()
	sv := server.Server{Driver: driver}
	err = sv.RegisterOSCAL(e)
	if err != nil {
		panic(err)
	}
	err = sv.RegisterRuntime(e)
	if err != nil {
		panic(err)
	}
	err = sv.RegisterProcess(e)
	if err != nil {
		panic(err)
	}
	err = e.Start(":8080")
	if err != nil {
		panic(err)
	}
}
