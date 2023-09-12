package jobs

import (
	"context"
	"fmt"
	"testing"

	oscal "github.com/compliance-framework/configuration-service/internal/models/oscal/v1_1"
	"github.com/compliance-framework/configuration-service/internal/models/runtime"
	"github.com/compliance-framework/configuration-service/internal/pubsub"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type FakeDriver struct {
	UpdateFn      func(id string, object interface{}) error
	CreateFn      func(id string, object interface{}) error
	CreateManyFn  func(objects map[string]interface{}) error
	GetFn         func(id string, object interface{}) error
	GetAllFn      func(ctx context.Context, collection string, object interface{}, filters ...map[string]interface{}) ([]interface{}, error)
	DeleteFn      func(id string) error
	DeleteWhereFn func(ctx context.Context, collection string, object interface{}, filters map[string]interface{}) error
}

func (f *FakeDriver) GetAll(ctx context.Context, collection string, object interface{}, filters ...map[string]interface{}) ([]interface{}, error) {
	return f.GetAllFn(ctx, collection, object, filters...)
}
func (f *FakeDriver) Update(_ context.Context, _, id string, object interface{}) error {
	return f.UpdateFn(id, object)
}
func (f *FakeDriver) Create(_ context.Context, _, id string, object interface{}) error {
	return f.CreateFn(id, object)
}

func (f *FakeDriver) Get(_ context.Context, _, id string, object interface{}) error {
	return f.GetFn(id, object)
}
func (f *FakeDriver) Delete(_ context.Context, _, id string) error {
	return f.DeleteFn(id)
}

func (f *FakeDriver) CreateMany(_ context.Context, _ string, objects map[string]interface{}) error {
	return f.CreateManyFn(objects)
}

func (f *FakeDriver) DeleteWhere(ctx context.Context, collection string, object interface{}, filters map[string]interface{}) error {
	return f.DeleteWhereFn(ctx, collection, object, filters)
}

type TestCase struct {
	name          string
	GetFn         func(id string, object interface{}) error
	UpdateFn      func(id string, object interface{}) error
	CreateFn      func(id string, object interface{}) error
	CreateManyFn  func(objects map[string]interface{}) error
	GetAllFn      func(ctx context.Context, collection string, object interface{}, filters ...map[string]interface{}) ([]interface{}, error)
	DeleteFn      func(id string) error
	DeleteWhereFn func(ctx context.Context, collection string, object interface{}, filters map[string]interface{}) error
	expectErr     string
	data          pubsub.Event
}

func TestCreateJobs(t *testing.T) {
	testCases := []TestCase{
		{
			name:      "no loading RuntimeConfiguration",
			data:      pubsub.Event{Data: pubsub.DatabaseEvent{Object: "foo", Type: "configurations"}},
			expectErr: "could not load data",
		},
		{
			name: "no assessment-plan",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				t := object.(*oscal.AssessmentPlan)
				t.Tasks = []*oscal.Task{{
					Uuid: "123",
				}}
				return fmt.Errorf("boom")
			},
			expectErr: "could not get assessment-plan",
		},
		{
			name: "no task-uuid",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "124"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				t := object.(*oscal.AssessmentPlan)
				t.Tasks = []*oscal.Task{{
					Uuid: "123",
				}}
				return nil
			},
			expectErr: "task 124 not found on assessment-plan",
		},
		{
			name: "success",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				t := object.(*oscal.AssessmentPlan)
				t.LocalDefinitions = &oscal.LocalDefinitions{
					Activities: []*oscal.CommonActivity{
						{
							Uuid: "123",
							Props: []*oscal.Property{
								{
									Name:  "foo",
									Value: "bar",
								},
							},
						},
					},
				}
				t.Tasks = []*oscal.Task{{
					Uuid: "123",
					AssociatedActivities: []*oscal.AssociatedActivity{{
						ActivityUuid: "123",
						Subjects: []*oscal.AssessmentSubject{
							{
								IncludeSubjects: []*oscal.SelectAssessmentSubject{
									{
										SubjectUuid: "123",
										Type:        "component",
									},
								},
							},
						},
					}},
				}}
				return nil
			},
			CreateFn: func(_ string, _ interface{}) error {
				return nil
			},
		},
	}
	f := FakeDriver{}
	r := RuntimeJobCreator{
		Driver: &f,
		Log:    zap.NewNop().Sugar(),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f.CreateFn = tc.CreateFn
			f.UpdateFn = tc.UpdateFn
			f.CreateManyFn = tc.CreateManyFn
			f.GetFn = tc.GetFn
			f.GetAllFn = tc.GetAllFn
			f.DeleteFn = tc.DeleteFn
			f.DeleteWhereFn = tc.DeleteWhereFn
			err := r.createJobs(tc.data)
			if tc.expectErr != "" {
				assert.ErrorContains(t, err, tc.expectErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestDeleteJobs(t *testing.T) {
	testCases := []TestCase{
		{
			name:      "no loading RuntimeConfiguration",
			data:      pubsub.Event{Data: pubsub.DatabaseEvent{Object: "foo", Type: "configurations"}},
			expectErr: "could not load data",
		},
		{
			name: "error jobs",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				return fmt.Errorf("boom")
			},
			expectErr: "could not get jobs",
		},
		{
			name: "error delete",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				obs := object.(*runtime.RuntimeConfigurationJob)
				obs.Uuid = "123"
				return nil
			},
			DeleteFn: func(id string) error {
				return fmt.Errorf("boom")
			},
			expectErr: "could not delete job",
		},
		{
			name: "success",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				obs := object.(*runtime.RuntimeConfigurationJob)
				obs.Uuid = "123"
				return nil
			},
			DeleteFn: func(id string) error {
				return nil
			},
		},
	}
	f := FakeDriver{}
	r := RuntimeJobCreator{
		Driver: &f,
		Log:    zap.NewNop().Sugar(),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f.CreateFn = tc.CreateFn
			f.UpdateFn = tc.UpdateFn
			f.CreateManyFn = tc.CreateManyFn
			f.GetFn = tc.GetFn
			f.GetAllFn = tc.GetAllFn
			f.DeleteFn = tc.DeleteFn
			f.DeleteWhereFn = tc.DeleteWhereFn
			err := r.deleteJobs(tc.data)
			if tc.expectErr != "" {
				assert.ErrorContains(t, err, tc.expectErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestUpdateJobs(t *testing.T) {
	testCases := []TestCase{
		{
			name:      "no loading RuntimeConfiguration",
			data:      pubsub.Event{Data: pubsub.DatabaseEvent{Object: "foo", Type: "configurations"}},
			expectErr: "could not load data",
		},
		{
			name: "no assessment-plan",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				switch t := object.(type) {
				case *oscal.AssessmentPlan:
					t.Tasks = []*oscal.Task{{
						Uuid: "123",
					}}
					return fmt.Errorf("boom")
				case *runtime.RuntimeConfigurationJob:
					t.Uuid = "123"
					return nil
				}
				return nil
			},
			expectErr: "could not get assessment-plan",
		},
		{
			name: "no task-uuid",
			data: pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "124"}, Type: "configurations"}},
			GetFn: func(id string, object interface{}) error {
				switch t := object.(type) {
				case *oscal.AssessmentPlan:
					t.Tasks = []*oscal.Task{{
						Uuid: "123",
					}}
					return nil
				case *runtime.RuntimeConfigurationJob:
					t.TaskId = "123"
					return nil
				}
				return nil
			},
			expectErr: "task 124 not found on assessment-plan",
		},
		{
			name:     "fail update",
			data:     pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123", Schedule: "1"}, Type: "configurations"}},
			UpdateFn: func(id string, object interface{}) error { return fmt.Errorf("boom") },
			GetFn: func(id string, object interface{}) error {
				switch t := object.(type) {
				case *oscal.AssessmentPlan:
					t.Tasks = []*oscal.Task{{
						Uuid: "123",
					}}
					t.LocalDefinitions = &oscal.LocalDefinitions{
						Activities: []*oscal.CommonActivity{
							{
								Uuid: "123",
							},
						},
					}
					return nil
				case *runtime.RuntimeConfigurationJob:
					t.TaskId = "123"
					return nil
				}
				return nil
			},
			expectErr: "could not update job",
		},
		{
			name:     "update success",
			data:     pubsub.Event{Data: pubsub.DatabaseEvent{Object: runtime.RuntimeConfiguration{AssessmentPlanUuid: "123", TaskUuid: "123"}, Type: "configurations"}},
			UpdateFn: func(id string, object interface{}) error { return nil },
			GetFn: func(id string, object interface{}) error {
				switch t := object.(type) {
				case *oscal.AssessmentPlan:
					t.Tasks = []*oscal.Task{{
						Uuid: "123",
					}}
					t.LocalDefinitions = &oscal.LocalDefinitions{
						Activities: []*oscal.CommonActivity{
							{
								Uuid: "123",
							},
						},
					}
					return nil
				case *runtime.RuntimeConfigurationJob:
					t.TaskId = "123"
					return nil
				}
				return nil
			},
		},
	}
	f := FakeDriver{}
	r := RuntimeJobCreator{
		Driver: &f,
		Log:    zap.NewNop().Sugar(),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f.CreateFn = tc.CreateFn
			f.UpdateFn = tc.UpdateFn
			f.CreateManyFn = tc.CreateManyFn
			f.GetFn = tc.GetFn
			f.GetAllFn = tc.GetAllFn
			f.DeleteFn = tc.DeleteFn
			f.DeleteWhereFn = tc.DeleteWhereFn
			err := r.updateJobs(tc.data)
			if tc.expectErr != "" {
				assert.ErrorContains(t, err, tc.expectErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
