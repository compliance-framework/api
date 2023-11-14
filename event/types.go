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

type ResultEvent struct{}
