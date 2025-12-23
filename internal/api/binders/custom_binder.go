package binders

import (
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
)

const (
	MIMEApplicationYAML = "application/yaml"
	MIMEApplicationJSON = "application/json"
)

type CustomBinder struct{}

func (cb *CustomBinder) Bind(i any, c echo.Context) error {
	req := c.Request()
	contentType := req.Header.Get(echo.HeaderContentType)
	switch contentType {
	case MIMEApplicationYAML:
		if err := yaml.NewDecoder(req.Body).Decode(i); err != nil && err != io.EOF {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error()).SetInternal(err)
		}
	case MIMEApplicationJSON:
		defaultBinder := new(echo.DefaultBinder)
		if err := defaultBinder.Bind(i, c); err != nil {
			return err
		}
	default:
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "Unsupported Media Type")
	}
	return nil
}
