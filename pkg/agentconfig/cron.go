package agentconfig

import (
	"errors"
	"fmt"
	"strings"

	"github.com/robfig/cron/v3"
)

var scheduleParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// ParseSchedule parses a plugin schedule the way the agent does: standard 5-field cron or a
// descriptor such as "@hourly". It is NOT the API's 6-field internal scheduler format.
//
// robfig/cron v3.0.1 panics on a TZ= or CRON_TZ= prefix with no space after it (it slices
// past the end of the spec), so that form is rejected first, and any other parser panic is
// returned as an error.
func ParseSchedule(expr string) (sched cron.Schedule, err error) {
	if strings.HasPrefix(expr, "TZ=") || strings.HasPrefix(expr, "CRON_TZ=") {
		if !strings.Contains(expr, " ") {
			return nil, errors.New("a time zone prefix must be followed by a space and a schedule")
		}
	}
	defer func() {
		if r := recover(); r != nil {
			sched, err = nil, fmt.Errorf("unparseable schedule: %v", r)
		}
	}()
	return scheduleParser.Parse(expr)
}
