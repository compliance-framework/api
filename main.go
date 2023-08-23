package main

import (
	_ "github.com/compliance-framework/configuration-service/internal/models"
	"github.com/compliance-framework/configuration-service/internal/server"
	_ "github.com/compliance-framework/configuration-service/internal/stores"
	"github.com/compliance-framework/configuration-service/internal/stores/file"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	sv := server.Server{Driver: &file.FileDriver{Path: "."}}
	err := sv.RegisterOSCAL(e)
	if err != nil {
		panic(err)
	}
	e.Start(":8080")
}
