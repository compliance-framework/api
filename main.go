package main

import (
	"github.com/compliance-framework/configuration-service/internal/jobs"
	_ "github.com/compliance-framework/configuration-service/internal/models"
	"github.com/compliance-framework/configuration-service/internal/server"
	_ "github.com/compliance-framework/configuration-service/internal/stores"
	"github.com/compliance-framework/configuration-service/internal/stores/file"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func main() {
	fileDriver := &file.FileDriver{Path: "."}
	e := echo.New()
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	sugar := logger.Sugar()
	e.Use(middleware.Logger())
	job := jobs.RuntimeJobCreator{Log: sugar, Driver: fileDriver}
	err = job.Init()
	if err != nil {
		panic(err)
	}
	go job.Run()
	//sv := server.Server{Driver: &mongo.MongoDriver{Url: "mongodb://127.0.0.1:27017", Database: "cf"}}
	sv := server.Server{Driver: fileDriver}
	err = sv.RegisterOSCAL(e)
	if err != nil {
		panic(err)
	}
	err = sv.RegisterRuntime(e)
	if err != nil {
		panic(err)
	}
	err = e.Start(":8080")
	if err != nil {
		panic(err)
	}
}
