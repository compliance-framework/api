package domain

import (
	"strconv"
	"strings"
	"time"
)

type Metadata struct {
	Revisions             []Revision `json:"revisions"`
	PartyUuids            []string   `json:"partyUuids"`
	ResponsiblePartyUuids []string   `json:"responsiblePartyUuids"`
	RoleUuids             []string   `json:"roleUuids"`
	Actions               []Action   `json:"actions"`
}

type Revision struct {
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Links       []Link     `json:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty"`

	Published    time.Time `json:"published"`
	LastModified time.Time `json:"lastModified"`
	Version      string    `json:"version"`
	OscalVersion string    `json:"oscalVersion"`
}

func NewRevision(title string, description string, remarks string) Revision {
	revision := Revision{
		Title:       title,
		Description: description,
		Remarks:     remarks,
		Version:     "1.0.0",
	}
	return revision
}

func (r *Revision) bumpVersion(part int, title string, description string, remarks string) Revision {
	versionParts := strings.Split(r.Version, ".")
	versionPart, err := strconv.Atoi(versionParts[part])
	if err != nil {
		return Revision{}
	}

	versionPart++
	versionParts[part] = strconv.Itoa(versionPart)
	version := strings.Join(versionParts, ".")

	return Revision{
		Title:       title,
		Description: description,
		Remarks:     remarks,
		Version:     version,
	}
}

func (r *Revision) BumpMajor(title string, description string, remarks string) Revision {
	return r.bumpVersion(0, title, description, remarks)
}

func (r *Revision) BumpMinor(title string, description string, remarks string) Revision {
	return r.bumpVersion(1, title, description, remarks)
}

func (r *Revision) BumpPatch(title string, description string, remarks string) Revision {
	return r.bumpVersion(2, title, description, remarks)
}
