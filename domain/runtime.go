package domain

type JobSpecification struct {
	RuntimeUuid string                    `json:"runtime-uuid"`
	Plan        AssessmentPlanInformation `json:"plan"`
}

type AssessmentPlanInformation struct {
	Uuid  string            `json:"uuid"`
	Title string            `json:"title"`
	Tasks []TaskInformation `json:"tasks"`
}

type TaskInformation struct {
	Uuid       string                `json:"uuid"`
	Title      string                `json:"title"`
	Schedule   string                `json:"schedule"`
	Selector   SubjectSelection      `json:"selector"`
	Activities []ActivityInformation `json:"activities"`
}

type ActivityInformation struct {
	Uuid     string                `json:"uuid"`
	Title    string                `json:"title"`
	Provider ProviderConfiguration `json:"provider"`
}
