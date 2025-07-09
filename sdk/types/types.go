package types

import (
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"time"
)

type Link oscalTypes_1_1_3.Link
type Property oscalTypes_1_1_3.Property

type OriginActor struct {
	UUID   uuid.UUID   `json:"uuid" yaml:"uuid"`
	Type   string      `json:"type" yaml:"type"`
	Title  string      `json:"title,omitempty" yaml:"title,omitempty"`
	RoleId string      `json:"role-id,omitempty" yaml:"role-id,omitempty"`
	Links  *[]Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props  *[]Property `json:"props,omitempty" yaml:"props,omitempty"`
}

type Origin struct {
	Actors []OriginActor `json:"actors" yaml:"actors"`
}

type Step struct {
	UUID        uuid.UUID  `json:"uuid,omitempty"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
}

type Activity struct {
	UUID        uuid.UUID  `json:"uuid,omitempty"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Steps       []Step     `json:"steps,omitempty"`
}

type ComponentIdentifier struct {
	Identifier string `json:"identifier,omitempty"`
}

type InventoryItem struct {
	// user/chris@linguine.tech
	// operating-system/ubuntu/22.4
	// web-server/ec2/i-12345
	Identifier string `json:"identifier,omitempty"`

	// "operating-system"	description="System software that manages computer hardware, software resources, and provides common services for computer programs."
	// "database"			description="An electronic collection of data, or information, that is specially organized for rapid search and retrieval."
	// "web-server"			description="A system that delivers content or services to end users over the Internet or an intranet."
	// "dns-server"			description="A system that resolves domain names to internet protocol (IP) addresses."
	// "email-server"		description="A computer system that sends and receives electronic mail messages."
	// "directory-server"	description="A system that stores, organizes and provides access to directory information in order to unify network resources."
	// "pbx"				description="A private branch exchange (PBX) provides a a private telephone switchboard."
	// "firewall"			description="A network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules."
	// "router"				description="A physical or virtual networking device that forwards data packets between computer networks."
	// "switch"				description="A physical or virtual networking device that connects devices within a computer network by using packet switching to receive and forward data to the destination device."
	// "storage-array"		description="A consolidated, block-level data storage capability."
	// "appliance"			description="A physical or virtual machine that centralizes hardware, software, or services for a specific purpose."
	Type                  string                `json:"type,omitempty"`
	Title                 string                `json:"title,omitempty"`
	Description           string                `json:"description,omitempty"`
	Remarks               string                `json:"remarks,omitempty"`
	Props                 []Property            `json:"props,omitempty"`
	Links                 []Link                `json:"links,omitempty"`
	ImplementedComponents []ComponentIdentifier `json:"implemented-components,omitempty"`
}

type PortRange struct {
	End       int    `json:"end,omitempty" yaml:"end,omitempty"`
	Start     int    `json:"start,omitempty" yaml:"start,omitempty"`
	Transport string `json:"transport,omitempty" yaml:"transport,omitempty"`
}

type Protocol struct {
	Name       string       `json:"name,omitempty" yaml:"name,omitempty"`
	PortRanges *[]PortRange `json:"port-ranges,omitempty" yaml:"port-ranges,omitempty"`
	Title      string       `json:"title,omitempty" yaml:"title,omitempty"`
	UUID       uuid.UUID    `json:"uuid,omitempty" yaml:"uuid,omitempty"`
}

type Component struct {
	// components/common/ssh
	// components/common/github-repository
	// components/common/github-organisation
	// components/common/ubuntu-22
	// components/internal/auth-policy
	Identifier string `json:"identifier,omitempty"`

	// Software
	// Service
	Type        string     `json:"type,omitempty"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`
	Purpose     string     `json:"purpose,omitempty"`
	Protocols   []Protocol `json:"protocols,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
}

type Subject struct {
	Identifier string `json:"identifier,omitempty"`

	// InventoryItem
	// Component
	Type string `json:"type,omitempty"`

	Description string     `json:"description,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
}

type ObjectiveStatus struct {
	Reason  string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Remarks string `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	State   string `json:"state" yaml:"state"`
}

type Evidence struct {
	// UUID needs to remain consistent for a piece of evidence being collected periodically.
	// It represents the "stream" of the same observation being made over time.
	// For the same checks, performed on the same machine, the UUID for each check should remain the same.
	// For the same check, performed on two different machines, the UUID should differ.
	UUID        uuid.UUID `json:"uuid,omitempty"`
	Title       string    `json:"title,omitempty"`
	Description string    `json:"description,omitempty"`
	Remarks     *string   `json:"remarks,omitempty"`

	// Assigning labels to Evidence makes it searchable and easily usable in the UI
	Labels map[string]string `json:"labels,omitempty"`

	// When did we start collecting the evidence, and when did the process end, and how long is it valid for ?
	Start   time.Time  `json:"start"`
	End     time.Time  `json:"end"`
	Expires *time.Time `json:"expires,omitempty"`

	Props []Property `json:"props,omitempty"`
	Links []Link     `json:"links,omitempty"`

	// Who or What is generating this evidence
	Origins []Origin `json:"origins,omitempty"`
	// What steps did we take to create this evidence
	Activities     []Activity      `json:"activities,omitempty"`
	InventoryItems []InventoryItem `json:"inventory-items,omitempty"`
	// Which components of the subject are being observed. A tool, user, policy etc.
	Components []Component `json:"components,omitempty"`
	// Who or What are we providing evidence for. What's under test.
	Subjects []Subject `json:"subjects,omitempty"`
	// Did we satisfy what was being tested for, or did we fail ?
	Status ObjectiveStatus `json:"status"`
}
