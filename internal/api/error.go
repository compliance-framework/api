package api

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

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

func FormatTagValidationError(err error, invalidObj any) Error {
	e := Error{}
	e.Errors = make(map[string]interface{})
	var errs validator.ValidationErrors

	if !errors.As(err, &errs) {
		return e
	}

	invalidObjType := reflect.TypeOf(invalidObj)

	if invalidObjType.Kind() == reflect.Ptr {
		invalidObjType = invalidObjType.Elem()
	}

	for _, v := range errs {
		fieldName := v.StructField()
		jsonTag := fieldName
		if f, ok := invalidObjType.FieldByName(fieldName); ok {
			tag := f.Tag.Get("json")
			if tag != "" && tag != "-" {
				jsonTag = strings.Split(tag, ",")[0]
			}
		}
		msg := fmt.Sprintf("validation failed on '%s'", v.Tag())
		if errList, ok := e.Errors[jsonTag].([]string); ok {
			e.Errors[jsonTag] = append(errList, msg)
		} else {
			e.Errors[jsonTag] = []string{msg}
		}
	}
	return e
}

func FormatOscalValidatorError(errors map[string]any) Error {
	return Error{Errors: errors}
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
