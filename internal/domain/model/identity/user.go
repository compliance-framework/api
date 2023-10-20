package identity

import (
	"github.com/compliance-framework/configuration-service/internal/domain/model"
)

// User A type of user that interacts with the system based on an associated role.
type User struct {
	AuthorizedPrivileges []CommonAuthorizedPrivilege `json:"authorized-privileges,omitempty"`

	// A summary of the user's purpose within the system.
	model.ComprehensiveDetails

	RoleIds []string `json:"role-ids,omitempty"`

	// A short common name, abbreviation, or acronym for the user.
	ShortName string `json:"short-name,omitempty"`

	// A name given to the user, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this user class elsewhere in this or other OSCAL instances. The locally defined UUID of the system user can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// CommonAuthorizedPrivilege Identifies a specific system privilege held by the user, along with an associated description and/or rationale for the privilege.
// NOTE: This is subject to change if we decide to implement another type of identity system
type CommonAuthorizedPrivilege struct {
	// A summary of the privilege's purpose within the system.
	Description        string   `json:"description,omitempty"`
	FunctionsPerformed []string `json:"functions-performed"`

	// A human-readable name for the privilege.
	Title string `json:"title"`
}
