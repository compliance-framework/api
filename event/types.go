package event

import "github.com/compliance-framework/configuration-service/domain"

type TopicType string

const (
	TopicTypePlan TopicType = "runtime.plan"
)

type Subscriber[T any] func(topic TopicType) (chan T, error)
type Publisher func(msg interface{}, topic TopicType) error

type PlanPublished struct {
	RuntimeId string
	// Type holds the type of the event: created / updated / deleted
	Type string
	domain.JobSpecification
}
