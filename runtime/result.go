package runtime

import (
	"time"

	"github.com/compliance-framework/configuration-service/domain"
	"github.com/google/uuid"
)

type ExecutionStatus int
type LogType int

const (
	ExecutionStatusSuccess ExecutionStatus = iota
	ExecutionStatusFailure
)

// ExecutionResult holds the result of an compliance check execution for each subject.
type ExecutionResult struct {
	Title        string            `json:"title" yaml:"title"`
	Status       ExecutionStatus   `json:"status" yaml:"status"`
	StreamId     uuid.UUID         `json:"streamId" yaml:"streamId"`
	ComponentId  string            `json:"componentId" yaml:"componentId"`
	ControlId    string            `json:"controlId" yaml:"controlId"`
	TaskId       string            `json:"taskId" yaml:"taskId"`
	ActivityId   string            `json:"activityId" yaml:"activityId"`
	Error        error             `json:"error" yaml:"error"`
	Subject      Subject           `json:"subject" yaml:"subject"`
	Observations []Observation     `json:"observations" yaml:"observations"`
	Findings     []Finding         `json:"findings" yaml:"findings"`
	Risks        []Risk            `json:"risks" yaml:"risks"`
	Logs         []LogEntry        `json:"logs" yaml:"logs"`
	Labels       map[string]string `json:"labels" yaml:"labels"`
}

type Observation struct {
	Id               string            `json:"id" yaml:"id"`
	Title            string            `json:"title" yaml:"title"`
	Description      string            `json:"description" yaml:"description"`
	Props            []domain.Property `json:"props" yaml:"props"`
	Links            []domain.Link     `json:"links" yaml:"links"`
	Remarks          string            `json:"remarks" yaml:"remarks"`
	SubjectId        string            `json:"subjectId" yaml:"subjectId"`
	Collected        time.Time         `json:"collected" yaml:"collected"`
	Expires          time.Time         `json:"expires" yaml:"expires"`
	RelevantEvidence []Evidence        `json:"relevantEvidence" yaml:"relevantEvidence"`
}

type Evidence struct {
	Title       string            `json:"title,omitempty" yaml:"title,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []domain.Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}

type Finding struct {
	Id          string            `json:"id" yaml:"id"`
	Title       string            `json:"title,omitempty" yaml:"title,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []domain.Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Tasks       []domain.Task     `json:"tasks,omitempty" yaml:"tasks,omitempty"`
	Remarks     string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Status      string            `json:"status,omitempty" yaml:"status,omitempty"`
	SubjectId   string            `json:"subjectId,omitempty" yaml:"subjectId,omitempty"`
}

type Subject struct {
	Id          string             `json:"id" yaml:"id"`
	SubjectId   string             `json:"subjectId" yaml:"subjectId"`
	Type        domain.SubjectType `json:"type" yaml:"type"`
	Title       string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description string             `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []domain.Property  `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []domain.Link      `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}

type Risk struct {
	Title       string            `json:"title" yaml:"title"`
	SubjectId   string            `json:"subjectId" yaml:"subjectId"`
	Description string            `json:"description" yaml:"description"`
	Statement   string            `json:"statement" yaml:"statement"`
	Props       []domain.Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty" yaml:"links,omitempty"`
}

type LogEntry struct {
	Title       string            `json:"title" yaml:"title"`
	SubjectId   string            `json:"subjectId" yaml:"subjectId"`
	Description string            `json:"description" yaml:"description"`
	Start       time.Time         `json:"start" yaml:"start"`
	End         time.Time         `json:"end" yaml:"end"`
	Remarks     string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Props       []domain.Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty" yaml:"links,omitempty"`
}
