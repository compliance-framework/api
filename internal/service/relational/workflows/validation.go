package workflows

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/uuid"
)

// ValidateNotNil checks if an entity is nil and returns an appropriate error
func ValidateNotNil(entity interface{}, entityName string) error {
	if entity == nil {
		return fmt.Errorf("%s cannot be nil", entityName)
	}
	// Handle typed nil pointers (e.g., (*StepExecution)(nil))
	val := reflect.ValueOf(entity)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return fmt.Errorf("%s cannot be nil", entityName)
	}
	return nil
}

// ValidateStringRequired checks if a required string field is empty
func ValidateStringRequired(value, fieldName string) error {
	if value == "" {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

// ValidateStringLength checks if a string exceeds the maximum length
func ValidateStringLength(value, fieldName string, maxLength int) error {
	if len(value) > maxLength {
		return fmt.Errorf("%s cannot exceed %d characters", fieldName, maxLength)
	}
	return nil
}

// ValidateUUIDRequired checks if a UUID pointer is nil
func ValidateUUIDRequired(id *uuid.UUID, fieldName string) error {
	if id == nil {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

// ValidateEnum checks if a value is in a list of valid options
// If required is true, empty values will return an error
func ValidateEnum(value string, validOptions []string, fieldName string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", fieldName)
		}
		return nil // Empty is valid if field is optional
	}

	for _, option := range validOptions {
		if value == option {
			return nil
		}
	}

	return fmt.Errorf("invalid %s: %s", fieldName, value)
}

// ValidateCadence validates a cadence value
func ValidateCadence(cadence string) error {
	return ValidateEnum(cadence, ValidCadences, "cadence", false)
}

// ValidateAssignmentType validates an assignment type
func ValidateAssignmentType(assignmentType string) error {
	return ValidateEnum(assignmentType, ValidAssignmentTypes, "assigned to type", true)
}

// ValidateWorkflowExecutionStatus validates a workflow execution status
func ValidateWorkflowExecutionStatus(status string) error {
	return ValidateEnum(status, ValidWorkflowExecutionStatuses, "status", true)
}

// ValidateStepExecutionStatus validates a step execution status
func ValidateStepExecutionStatus(status string) error {
	return ValidateEnum(status, ValidStepExecutionStatuses, "status", true)
}

// ValidateTriggerType validates a trigger type
func ValidateTriggerType(triggerType string) error {
	return ValidateEnum(triggerType, ValidTriggerTypes, "triggered by", true)
}

// ValidateRelationshipType validates a control relationship type
func ValidateRelationshipType(relationshipType string) error {
	return ValidateEnum(relationshipType, ValidRelationshipTypes, "relationship type", false)
}

// ValidateRelationshipStrength validates a control relationship strength
func ValidateRelationshipStrength(strength string) error {
	return ValidateEnum(strength, ValidRelationshipStrengths, "strength", false)
}

// CombineErrors combines multiple validation errors into a single error
func CombineErrors(errs ...error) error {
	var validErrs []error
	for _, err := range errs {
		if err != nil {
			validErrs = append(validErrs, err)
		}
	}

	if len(validErrs) == 0 {
		return nil
	}

	if len(validErrs) == 1 {
		return validErrs[0]
	}

	return errors.Join(validErrs...)
}
