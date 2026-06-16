package worker

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
)

const (
	JobTypeDashboardSuggestionCell = "dashboard_suggestion_cell"
	DashboardSuggestionQueue       = "suggestion"
	DashboardSuggestionMaxAttempts = 3
)

var (
	ErrDashboardSuggestionWorkerDisabled      = errors.New("dashboard suggestion worker is disabled")
	ErrDashboardSuggestionWorkerNotRegistered = errors.New("dashboard suggestion worker is not registered")
)

type DashboardSuggestionCellArgs struct {
	RunID     uuid.UUID `json:"run_id" river:"unique"`
	CellIndex int       `json:"cell_index" river:"unique"`
}

func (DashboardSuggestionCellArgs) Kind() string { return JobTypeDashboardSuggestionCell }

func (DashboardSuggestionCellArgs) Timeout() time.Duration { return 5 * time.Minute }

func JobInsertOptionsForDashboardSuggestionCell() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       DashboardSuggestionQueue,
		MaxAttempts: DashboardSuggestionMaxAttempts,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
		},
	}
}
