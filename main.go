package main

import (
	server "github.com/compliance-framework/configuration-service/internal/server"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	err := server.Register(e)
	if err != nil {
		panic(err)
	}
	err = e.Start(":8080")
	if err != nil {
		panic(err)
	}
}
