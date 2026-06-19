package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFailMode(t *testing.T) {
	require.Equal(t, FailOpen, ParseFailMode("open"))
	require.Equal(t, FailClosed, ParseFailMode("closed"))
	require.Equal(t, FailClosed, ParseFailMode(""))
	require.Equal(t, FailClosed, ParseFailMode("garbage"))
}

func TestDriversIncludesBuiltin(t *testing.T) {
	require.Contains(t, Drivers(), DriverBuiltin)
}

func TestOpenUnknownDriver(t *testing.T) {
	_, err := Open("does-not-exist", Options{})
	require.Error(t, err)
}

func TestRegisterNilPanics(t *testing.T) {
	require.Panics(t, func() { Register("authz-test-nil", nil) })
}

func TestRegisterDuplicatePanics(t *testing.T) {
	factory := func(Options) (PDP, error) { return nil, nil }
	Register("authz-test-dup", factory)
	require.Panics(t, func() { Register("authz-test-dup", factory) })
}

func TestOpenRegisteredDriver(t *testing.T) {
	want := &fakePDP{}
	Register("authz-test-open", func(Options) (PDP, error) { return want, nil })
	got, err := Open("authz-test-open", Options{})
	require.NoError(t, err)
	require.Same(t, want, got)
}

type fakePDP struct{}

func (fakePDP) Evaluate(context.Context, Subject, string, Resource, map[string]any) (Decision, error) {
	return Decision{Allow: true}, nil
}
func (fakePDP) Evaluations(context.Context, []EvalRequest) ([]Decision, error) { return nil, nil }
