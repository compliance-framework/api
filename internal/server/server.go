package server

import (
	"fmt"
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
	echo "github.com/labstack/echo/v4"
)

func Register(e *echo.Echo) error {
	models := schema.GetAll()
	for name, model := range models {
		routePref := fmt.Sprintf("/%s", name)
		route := fmt.Sprintf("/%s/:id", name)
		e.POST(routePref, genPOST(model))
		e.GET(route, genGET(model))
		e.DELETE(route, genDELETE(model))
		e.PUT(route, genPUT(model))
	}
	return nil
}

func genGET(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, "bad request")
		}
		// GET from database here
		return c.JSON(http.StatusOK, p)
	}
}

func genPOST(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, "bad request")
		}
		// POST from database here
		return c.JSON(http.StatusOK, p)
	}
}

func genPUT(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, "bad request")
		}
		// POST from database here
		return c.JSON(http.StatusOK, p)
	}
}

func genDELETE(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, "bad request")
		}
		// POST from database here
		return c.JSON(http.StatusOK, p)
	}
}
