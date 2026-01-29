package workflows

// Field length constraints
const (
	MaxNameLength          = 255
	MaxDescriptionLength   = 1000
	MaxRoleNameLength      = 255
	MaxControlIDLength     = 255
	MaxControlSourceLength = 100
	MaxAssignedToIDLength  = 255
)

// Valid cadence values for workflow scheduling
var ValidCadences = []string{
	"daily",
	"weekly",
	"monthly",
	"quarterly",
	"annually",
}

// Valid assignment types for role assignments and step executions
var ValidAssignmentTypes = []string{
	"user",
	"group",
	"email",
}

// Valid workflow execution statuses
var ValidWorkflowExecutionStatuses = []string{
	"pending",
	"in_progress",
	"completed",
	"failed",
	"cancelled",
}

// Valid step execution statuses
var ValidStepExecutionStatuses = []string{
	"pending",
	"blocked",
	"in_progress",
	"completed",
	"failed",
	"skipped",
}

// Valid trigger types for workflow execution
var ValidTriggerTypes = []string{
	"manual",
	"scheduled",
	"automatic",
}

// Valid control relationship types
var ValidRelationshipTypes = []string{
	"satisfies",
	"partially_satisfies",
	"supports",
}

// Valid control relationship strengths
var ValidRelationshipStrengths = []string{
	"primary",
	"secondary",
	"supporting",
}
