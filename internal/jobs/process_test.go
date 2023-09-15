package jobs

import (
	"testing"

	process "github.com/compliance-framework/configuration-service/internal/models/process"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

func TestProcess(t *testing.T) {
	testCases := []struct {
		name             string
		assessmentResult process.AssessmentResult
		CreateFn         func(id string, object interface{}) error
	}{
		{
			name: "creates-result",
			assessmentResult: process.AssessmentResult{
				Id: "1234",
			},
			CreateFn: func(id string, object interface{}) error { return nil },
		}}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := FakeDriver{}
			f.CreateFn = tc.CreateFn
			testCase := testCases[i]
			processJob := &ProcessJob{
				Driver: &f,
				ch:     make(chan *nats.Msg),
				Log:    zap.NewExample().Sugar(),
			}
			err := processJob.SaveAssessmentResult(testCase.assessmentResult)

			if f.calls.Create == 0 {
				t.Errorf("expected Create to be called")
			}
			if err != nil {
				t.Errorf("failed to save assessment result: %s", err)
			}
		})
	}
}
