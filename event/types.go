package event

import "github.com/compliance-framework/configuration-service/domain"

type TopicType string

const (
	TopicTypePlan TopicType = "runtime.plan"
)

type Subscriber[T any] func(topic TopicType) (chan T, error)
type Publisher func(msg interface{}, topic TopicType) error

type PlanPublished struct {
	domain.JobSpecification
}
