package api

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"

	"github.com/labstack/echo/v4"
)

type Error struct {
	Errors map[string]any `json:"errors" yaml:"errors"`
}

func NewError(err error) Error {
	e := Error{}
	e.Errors = make(map[string]any)
	var v *echo.HTTPError
	switch {
	case errors.As(err, &v):
		e.Errors["body"] = v.Message
	default:
		e.Errors["body"] = err.Error()
	}
	return e
}

func Validator(err error) Error {
	e := Error{}
	e.Errors = make(map[string]any)
	var errs validator.ValidationErrors
	errors.As(err, &errs)
	for _, v := range errs {
		e.Errors[v.Field()] = fmt.Sprintf("%v", v.Tag())
	}
	return e
}

func AccessForbidden() Error {
	e := Error{}
	e.Errors = make(map[string]any)
	e.Errors["body"] = "access forbidden"
	return e
}

// InternalServerError is the client-facing body for a 5xx. It is deliberately generic: NewError
// serialises err.Error() verbatim, so handing it a driver error leaks constraint names, column
// names and SQL state to the caller. Log the real error server-side and return this instead.
func InternalServerError() Error {
	e := Error{}
	e.Errors = make(map[string]any)
	e.Errors["body"] = "internal server error"
	return e
}

func NotFound() Error {
	e := Error{}
	e.Errors = make(map[string]any)
	e.Errors["body"] = "resource not found"
	return e
}

func NotFoundCustomMsg(msg string) Error {
	e := Error{}
	e.Errors = make(map[string]any)
	e.Errors["body"] = msg
	return e
}

func InvalidUUID() Error {
	e := Error{}
	e.Errors = make(map[string]any)
	e.Errors["body"] = "invalid UUID"
	return e
}

func InvalidFutureTime(t time.Time) Error {
	e := Error{}
	e.Errors = make(map[string]any)
	e.Errors["body"] = fmt.Sprintf("time %s must not be in the future", t.Format(time.RFC3339Nano))
	return e
}
