package api

import (
	"errors"
	"fmt"
	"net/http"

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

func NotFound() Error {
	e := Error{}
	e.Errors = make(map[string]any)
	e.Errors["body"] = "resource not found"
	return e
}

func NotFoundError(err error) *echo.HTTPError {
	return &echo.HTTPError{
		Code:     http.StatusNotFound,
		Message:  "resource not found",
		Internal: err,
	}
}

func InvalidUUIDError(err error) *echo.HTTPError {
	return &echo.HTTPError{
		Code:     http.StatusBadRequest,
		Message:  fmt.Sprintf("invalid UUID: %v", err),
		Internal: err,
	}
}
