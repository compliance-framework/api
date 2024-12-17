package domain

import (
	"strconv"
	"strings"
	"time"
)

type Metadata struct {
	Revisions             []Revision `json:"revisions" yaml:"revisions"`
	PartyUuids            []string   `json:"partyUuids" yaml:"partyUuids"`
	ResponsiblePartyUuids []string   `json:"responsiblePartyUuids" yaml:"responsiblePartyUuids"`
	RoleUuids             []string   `json:"roleUuids" yaml:"roleUuids"`
	Actions               []Action   `json:"actions" yaml:"actions"`
}

type Revision struct {
	Title       string     `json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	Published    time.Time `json:"published" yaml:"published"`
	LastModified time.Time `json:"lastModified" yaml:"lastModified"`
	Version      string    `json:"version" yaml:"version"`
	OscalVersion string    `json:"oscalVersion" yaml:"oscalVersion"`
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
