package binders

import (
	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
)

const (
	MIMEApplicationYAML = "application/yaml"
	MIMEApplicationJSON = "application/json"
)

type CustomBinder struct{}

func (cb *CustomBinder) Bind(i interface{}, c echo.Context) error {
	req := c.Request()
	contentType := req.Header.Get(echo.HeaderContentType)

	if contentType == MIMEApplicationYAML {
		if err := yaml.NewDecoder(req.Body).Decode(i); err != nil && err != io.EOF {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error()).SetInternal(err)
		}
	} else if contentType == MIMEApplicationJSON {
		defaultBinder := new(echo.DefaultBinder)
		if err := defaultBinder.Bind(i, c); err != nil {
			return err
		}
	} else {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "Unsupported Media Type")
	}
	return nil
}
