package event

import "github.com/compliance-framework/configuration-service/domain"

type TopicType string

const (
	TopicTypePlan TopicType = "runtime.plan"
)

type Subscriber[T any] func(topic TopicType) (chan T, error)
type Publisher func(msg interface{}, topic TopicType) error

type PlanCreated struct {
	// Uuid of the new assessment plan
	Uuid domain.Uuid `yaml:"uuid" json:"uuid"`
}

type PlanUpdated struct {
	// Uuid of the updated assessment plan
	Uuid domain.Uuid `yaml:"uuid" json:"uuid"`
}
