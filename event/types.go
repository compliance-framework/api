package event

import "github.com/compliance-framework/configuration-service/domain"

type TopicType string

const (
	TopicTypePlan   TopicType = "runtime.configuration"
	TopicTypeResult TopicType = "job.result"
)

type Subscriber[T any] func(topic TopicType) (chan T, error)
type Publisher func(msg interface{}, topic TopicType) error

type PlanEvent struct {
	// Type holds the type of the event: created / updated / deleted
	Type                    string `yaml:"type" json:"type"`
	domain.JobSpecification `yaml:"data" json:"data"`
}

// ResultEvent TODO: Refactor this to use the same type as the one in the domain package
type ResultEvent struct {
	AssessmentId string `json:"assessment-id"`
	ComponentId  string `json:"component-id"`
	ControlId    string `json:"control-id"`
	TaskId       string `json:"task-id"`
	ActivityId   string `json:"activity-id"`
	Error        error  `json:"error"`
	Results      struct {
		Observations []domain.Observation `json:"observations"`
		Findings     []domain.Finding     `json:"findings"`
		Risks        []domain.Risk        `json:"risks"`
		Logs         []domain.LogEntry    `json:"logs"`
	} `json:"results"`
}
