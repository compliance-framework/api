package binders

import (
	"io"
	"net/http"

	"github.com/labstack/echo/v5"
	"gopkg.in/yaml.v2"
)

const (
	MIMEApplicationYAML = "application/yaml"
	MIMEApplicationJSON = "application/json"
)

type CustomBinder struct{}

func (cb *CustomBinder) Bind(c *echo.Context, i any) error {
	req := c.Request()
	contentType := req.Header.Get(echo.HeaderContentType)
	switch contentType {
	case MIMEApplicationYAML:
		if err := yaml.NewDecoder(req.Body).Decode(i); err != nil && err != io.EOF {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error()).Wrap(err)
		}
	case MIMEApplicationJSON:
		defaultBinder := new(echo.DefaultBinder)
		if err := defaultBinder.Bind(c, i); err != nil {
			return err
		}
	default:
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "Unsupported Media Type")
	}
	return nil
}
