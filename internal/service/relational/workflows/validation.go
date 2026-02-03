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
	if cadence == "" {
		return nil
	}
	if !CadenceType(cadence).IsValid() {
		return errors.New("invalid cadence value")
	}
	return nil
}

// ValidateAssignmentType validates an assignment type
func ValidateAssignmentType(assignmentType string) error {
	if assignmentType == "" {
		return errors.New("assigned to type is required")
	}
	if !AssignmentType(assignmentType).IsValid() {
		return errors.New("invalid assigned to type")
	}
	return nil
}

// ValidateWorkflowExecutionStatus validates a workflow execution status
func ValidateWorkflowExecutionStatus(status string) error {
	if status == "" {
		return errors.New("status is required")
	}
	if !WorkflowExecutionStatus(status).IsValid() {
		return errors.New("invalid status")
	}
	return nil
}

// ValidateStepExecutionStatus validates a step execution status
func ValidateStepExecutionStatus(status string) error {
	if status == "" {
		return errors.New("status is required")
	}
	if !StepExecutionStatus(status).IsValid() {
		return errors.New("invalid status")
	}
	return nil
}

// ValidateTriggerType validates a trigger type
func ValidateTriggerType(triggerType string) error {
	if triggerType == "" {
		return errors.New("triggered by is required")
	}
	if !TriggerType(triggerType).IsValid() {
		return errors.New("invalid triggered by")
	}
	return nil
}

// ValidateRelationshipType validates a control relationship type
func ValidateRelationshipType(relationshipType string) error {
	if relationshipType == "" {
		return nil
	}
	if !RelationshipType(relationshipType).IsValid() {
		return errors.New("invalid relationship type")
	}
	return nil
}

// ValidateRelationshipStrength validates a control relationship strength
func ValidateRelationshipStrength(strength string) error {
	if strength == "" {
		return nil
	}
	if !RelationshipStrength(strength).IsValid() {
		return errors.New("invalid strength")
	}
	return nil
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
