package runtime

import (
	"github.com/compliance-framework/configuration-service/domain"
	"time"
)

type ExecutionStatus int
type LogType int

const (
	ExecutionStatusSuccess ExecutionStatus = iota
	ExecutionStatusFailure
)

// ExecutionResult holds the result of an compliance check execution for each subject.
type ExecutionResult struct {
	Status       ExecutionStatus `json:"status"`
	AssessmentId string          `json:"assessmentId"`
	ComponentId  string          `json:"componentId"`
	ControlId    string          `json:"controlId"`
	TaskId       string          `json:"taskId"`
	ActivityId   string          `json:"activityId"`
	Error        error           `json:"error"`
	Subject      Subject         `json:"subject"`
	Observations []Observation   `json:"observations"`
	Findings     []Finding       `json:"findings"`
	Risks        []Risk          `json:"risks"`
	Logs         []LogEntry      `json:"logs"`
}

type Observation struct {
	Id               string            `json:"id"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Props            []domain.Property `json:"props"`
	Links            []domain.Link     `json:"links"`
	Remarks          string            `json:"remarks"`
	SubjectId        string            `json:"subjectId"`
	Collected        time.Time         `json:"collected"`
	Expires          time.Time         `json:"expires"`
	RelevantEvidence []Evidence        `json:"relevantEvidence"`
}

type Evidence struct {
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Props       []domain.Property `json:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty"`
	Remarks     string            `json:"remarks,omitempty"`
}

type Finding struct {
	Id          string            `json:"id"`
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Props       []domain.Property `json:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty"`
	Remarks     string            `json:"remarks,omitempty"`
	SubjectId   string            `json:"subjectId,omitempty"`
}

type Subject struct {
	Id          string             `json:"id"`
	SubjectId   string             `json:"subjectId"`
	Type        domain.SubjectType `json:"type"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description,omitempty"`
	Props       []domain.Property  `json:"props,omitempty"`
	Links       []domain.Link      `json:"links,omitempty"`
	Remarks     string             `json:"remarks,omitempty"`
}

type Risk struct {
	Title       string            `json:"title"`
	SubjectId   string            `json:"subjectId"`
	Description string            `json:"description"`
	Statement   string            `json:"statement"`
	Props       []domain.Property `json:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty"`
}

type LogEntry struct {
	Title       string            `json:"title"`
	SubjectId   string            `json:"subjectId"`
	Description string            `json:"description"`
	Start       time.Time         `json:"start"`
	End         time.Time         `json:"end"`
	Remarks     string            `json:"remarks,omitempty"`
	Props       []domain.Property `json:"props,omitempty"`
	Links       []domain.Link     `json:"links,omitempty"`
}
