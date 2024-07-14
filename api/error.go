package api

import (
	"errors"
	"fmt"

	"github.com/go-playground/validator/v10"

	"github.com/labstack/echo/v4"
)

type Error struct {
	Errors map[string]interface{} `json:"errors" yaml:"errors"`
}

func NewError(err error) Error {
	e := Error{}
	e.Errors = make(map[string]interface{})
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
	e.Errors = make(map[string]interface{})
	var errs validator.ValidationErrors
	errors.As(err, &errs)
	for _, v := range errs {
		e.Errors[v.Field()] = fmt.Sprintf("%v", v.Tag())
	}
	return e
}

func AccessForbidden() Error {
	e := Error{}
	e.Errors = make(map[string]interface{})
	e.Errors["body"] = "access forbidden"
	return e
}

func NotFound() Error {
	e := Error{}
	e.Errors = make(map[string]interface{})
	e.Errors["body"] = "resource not found"
	return e
}
