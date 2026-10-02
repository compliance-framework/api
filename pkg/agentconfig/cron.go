package agentconfig

import "github.com/robfig/cron/v3"

var scheduleParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// ParseSchedule parses a plugin schedule the way the agent does: standard 5-field cron or a
// descriptor such as "@hourly". It is NOT the API's 6-field internal scheduler format.
func ParseSchedule(expr string) (cron.Schedule, error) {
	return scheduleParser.Parse(expr)
}
