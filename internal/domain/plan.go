package domain

import (
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
)

import (
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// Plan
//
// An assessment plan, such as those provided by a FedRAMP assessor.
// Here are some real-world examples for Assets, Platforms, Subjects and Inventory Items within an OSCAL Assessment Plan:
//
// 1. Assets: This could be something like a customer database within a retail company. It's an asset because it's crucial to the business operation, storing all the essential customer details such as addresses, contact information, and purchase history.
// 2. Platforms: This could be the retail company's online E-commerce platform which hosts their online store, and where transactions occur. The platform might involve web servers, database servers, or a cloud environment.
// 3. Subjects: If the company is performing a security assessment, the subject could be the encryption method or security protocols used to protect the customer data while in transit or at rest in the database.
// 4. Inventory Items: These could be the individual servers or workstations used within the company. Inventory workstations are the physical machines or software applications used by employees that may have vulnerabilities or exposure to risk that need to be tracked and mitigated.
//
// Relation between Tasks, Activities and Steps:
//
// Scenario: Conducting a cybersecurity assessment of an organization's systems.
//
// 1. Task: The major task could be "Conduct vulnerability scanning on servers."
// 2. Activity: Within this task, an activity could be "Prepare servers for vulnerability scan."
// 3. Step: The steps that make up this activity could be things like:
//   - "Identify all servers"
//   - "Ensure necessary permissions are in place for scanning"
//   - "Check that scanning software is properly installed and updated."
//
// Another activity under the same task could be "Execute vulnerability scanning," and steps for that activity might include:
//
// 1. "Begin scanning process through scanning software."
// 2. "Monitor progress of scan."
// 3. "Document any issues or vulnerabilities identified."
//
// The process would continue like this with tasks broken down into activities, and activities broken down into steps.
//
// These concepts still apply in the context of automated tools or systems. In fact, the OSCAL model is designed to support both manual and automated processes.
// 1.	Task: The major task could be “Automated Compliance Checking”
// 2.	Activity: This task could have multiple activities such as:
// ▪	“Configure Automated Tool with necessary parameters”
// ▪	“Run Compliance Check”
// ▪	“Collect and Analyze Compliance Data”
// 3.	Step: In each of these activities, there are several subprocesses or actions (Steps). For example, under “Configure Automated Tool with necessary parameters”, the steps could be:
// ▪	“Define the criteria based on selected standards”
// ▪	“Set the scope or target systems for the assessment”
// ▪	“Specify the output (report) format”
// In context of an automated compliance check, the description of Task, Activity, and Step provides a systematic plan or procedure that the tool is expected to follow. This breakdown of tasks, activities, and steps could also supply useful context and explain the tool’s operation and results to system admins, auditors or other stakeholders. It also allows for easier troubleshooting in the event of problems.
type Plan struct {
	UUID                         *uuid.UUID         `bson:"_id" json:"uuid" yaml:"uuid"`
	ResultFilter                 labelfilter.Filter `bson:"resultFilter" json:"resultFilter" yaml:"resultFilter"`
	oscaltypes113.AssessmentPlan `bson:",inline"`
}

type TaskType string

const (
	TaskTypeMilestone TaskType = "milestone"
	TaskTypeAction    TaskType = "action"
)

type SubjectType string

const (
	SubjectTypeComponent     SubjectType = "component"
	SubjectTypeInventoryItem SubjectType = "inventoryItem"
	SubjectTypeLocation      SubjectType = "location"
	SubjectTypeParty         SubjectType = "party"
	SubjectTypeUser          SubjectType = "user"
)
