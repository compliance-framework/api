package handler

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/labstack/echo/v4"
)

// HTTP header names used by the agent-configuration routes.
const (
	headerETag        = "ETag"
	headerIfMatch     = "If-Match"
	headerIfNoneMatch = "If-None-Match"
)

// bodyError is a request-body problem with the HTTP status it maps to.
type bodyError struct {
	status int
	msg    string
}

func (e *bodyError) Error() string { return e.msg }

// respond writes the error as an api.Error body.
func (e *bodyError) respond(ctx echo.Context) error {
	return ctx.JSON(e.status, api.NewError(errors.New(e.msg)))
}

// readJSONBody reads a JSON request body for the agent-configuration handlers (R13). They do
// not use ctx.Bind, because CustomBinder rejects "application/json; charset=utf-8". A missing
// Content-Type or any application/json media type (with parameters) is accepted; any other
// type is 415. More than limit bytes is 413. An empty body returns nil.
func readJSONBody(ctx echo.Context, limit int64) ([]byte, *bodyError) {
	if ct := strings.TrimSpace(ctx.Request().Header.Get(echo.HeaderContentType)); ct != "" {
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || !strings.EqualFold(mediaType, echo.MIMEApplicationJSON) {
			return nil, &bodyError{status: http.StatusUnsupportedMediaType, msg: "request body must be application/json"}
		}
	}
	body := ctx.Request().Body
	if body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(http.MaxBytesReader(ctx.Response(), body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &bodyError{status: http.StatusRequestEntityTooLarge, msg: fmt.Sprintf("request body exceeds %d bytes", limit)}
		}
		return nil, &bodyError{status: http.StatusBadRequest, msg: "failed to read request body"}
	}
	return data, nil
}
