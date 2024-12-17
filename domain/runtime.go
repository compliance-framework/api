package domain

// JobSpecification is the model used to communicate with the runtime
// It is used to publish a plan to the runtime. The runtime will then
// use the information to execute the activities and publish the results back to the control-plane.
// Here's an example tailored specifically for Azure Cloud:
// Task: "Assess Azure cloud's storage security configuration."
// Activities could include:
// - "Review the Azure Blob storage access policies and Private Endpoint settings."
// - "Check for encryption at rest and in transit for Azure storage accounts."
// - "Evaluate Azure Shared Access Signatures (SAS) and Azure Storage Service Encryption (SSE)."
// One more example:
// Task: "Verify Azure network security settings."
// Activities could include:
// - "Review Azure Network Security Groups (NSGs) to ensure least privilege access."
// - "Assess Virtual Private Network (VPN) and ExpressRoute configurations for secure connectivity."
// - "Check Azure DDoS Protection settings to ensure resilience against DDoS attacks."
// In this scenario, the task provides the overall direction for the assessment (e.g., assessing storage security or network security on Azure),
// while the activities break this task down into smaller, concrete steps to follow.
type JobSpecification struct {
	Id          string            `json:"id" yaml:"id"`
	Title       string            `json:"title" yaml:"title"`
	PlanId      string            `json:"assessment-plan-id" yaml:"assessment-plan-id"`
	ComponentId string            `json:"component-id" yaml:"component-id"`
	ControlId   string            `json:"control-id" yaml:"control-id"`
	Tasks       []TaskInformation `json:"tasks" yaml:"tasks"`
}

type TaskInformation struct {
	Id         string                `json:"id" yaml:"id"`
	Title      string                `json:"title" yaml:"title"`
	Schedule   string                `json:"schedule" yaml:"schedule"`
	Activities []ActivityInformation `json:"activities" yaml:"activities"`
}

type ActivityInformation struct {
	Id       string           `json:"id" yaml:"id"`
	Title    string           `json:"title" yaml:"title"`
	Selector SubjectSelection `json:"selector" yaml:"selector"`
	Provider Provider         `json:"provider" yaml:"provider"`
}
