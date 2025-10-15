package oscalvalidator

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema"
)

//go:embed oscal_complete_schema.json
var schemaFiles embed.FS

var SchemaName = "oscal_complete_schema.json"

// Validates a full OSCAL structure (i.e. one of SSP) and returns errors mapped
func ValidateOscalAgainstSchema(obj any, componentCategory string, componentName string) (map[string]any, error) {
	compiler := jsonschema.NewCompiler()

	definitionName := fmt.Sprintf("#/definitions/%s:%s", componentCategory, componentName)
	fullName := fmt.Sprintf("%s%s", SchemaName, definitionName)

	// Open the schema (embedded so it is available in local memory)
	f, err := schemaFiles.Open(SchemaName)
	if err != nil {
		return nil, fmt.Errorf("open schema %s: %w", "oscal_complete_schema.json", err)
	}
	defer f.Close()

	// Add in-memory json to the compiler
	if err := compiler.AddResource("oscal_complete_schema.json", f); err != nil {
		return nil, fmt.Errorf("add resource %s: %w", "oscal_complete_schema.json", err)
	}

	// Compile the component we wish to validate
	schema, err := compiler.Compile(fullName)
	if err != nil {
		return nil, fmt.Errorf("compile schema %s: %w", fullName, err)
	}
	jsonObj, err := json.Marshal(obj)

	// Validate the marshalled oscal object
	fmt.Println("Validating ", obj)
	if err := schema.Validate(bytes.NewReader(jsonObj)); err != nil {
		if ve, ok := err.(*jsonschema.ValidationError); ok {
			extractedErrors := extractValidationErrors(ve)
			if len(extractedErrors) == 0 {
				return nil, nil
			}
			return extractedErrors, nil
		} else {
			return nil, err
		}
	}
	return nil, nil
}

func extractValidationErrors(err *jsonschema.ValidationError) map[string]any {
	errors := make(map[string]any)
	// Traverse the validation errors, until there exsits one without causes
	var traverse func(e *jsonschema.ValidationError)
	traverse = func(e *jsonschema.ValidationError) {
		// Leaf node
		if len(e.Causes) == 0 {
			field := pointerToField(e.InstancePtr)
			if field == "" {
				return // skip irrelevant branches
			}
			// Make message similar to validator
			fieldName := path.Base(field)

			msg := fmt.Sprintf("Field validation for '%s' failed: %s", fieldName, e.Message)

			errors[fieldName] = msg
			return
		}

		// Recurse
		for _, c := range e.Causes {
			traverse(c)
		}
	}

	traverse(err)
	return errors
}

func pointerToField(ptr string) string {
	if ptr == "" || ptr == "/" {
		return ""
	}

	parts := strings.Split(ptr, "/")[1:]
	for i, part := range parts {
		// convert /users/0/uuid -> users[0].uuid
		if _, err := strconv.Atoi(part); err == nil && i > 0 {
			parts[i-1] = parts[i-1] + "[" + part + "]"
			parts[i] = ""
		}
	}

	var fields []string
	for _, p := range parts {
		if p != "" {
			fields = append(fields, p)
		}
	}
	return strings.Join(fields, ".")
}
