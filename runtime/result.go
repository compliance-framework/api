package runtime

type ExecutionStatus int
type LogType int

const (
	ExecutionStatusSuccess ExecutionStatus = iota
	ExecutionStatusFailure
)

type ResultEvent struct {
	AssessmentId string `json:"assessmentId"`
	ComponentId  string `json:"componentId"`
	ControlId    string `json:"controlId"`
	TaskId       string `json:"taskId"`
	ActivityId   string `json:"activityId"`
	Error        error  `json:"error"`
	Results      struct {
		Observations []Observation `json:"observations"`
		Risks        []Risk        `json:"risks"`
	}
}

type Observation struct {
	Id          string `json:"id"`
	SubjectId   string `json:"subjectId"`
	Collected   string `json:"collected"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Expires     string `json:"expires"`
	Remarks     string `json:"remarks"`
}

type Risk struct {
	SubjectId   string `json:"subjectId"`
	Description string `json:"description"`
	Score       int32
}
