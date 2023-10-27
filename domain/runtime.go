package domain

type JobSpecification struct {
	Id    string            `json:"id"`
	Title string            `json:"title"`
	Tasks []TaskInformation `json:"tasks"`
}

type TaskInformation struct {
	Id         string                `json:"id"`
	Title      string                `json:"title"`
	Schedule   string                `json:"schedule"`
	Selector   SubjectSelection      `json:"selector"`
	Activities []ActivityInformation `json:"activities"`
}

type ActivityInformation struct {
	Id       string                `json:"id"`
	Title    string                `json:"title"`
	Provider ProviderConfiguration `json:"provider"`
}
