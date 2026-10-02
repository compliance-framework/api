// Package subjects lists the entities evidence can name as its subject: defined components,
// SSP system components, parties and users.
package subjects

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Kind is the kind of entity a subject is.
type Kind string

const (
	KindDefinedComponent Kind = "defined-component"
	KindSystemComponent  Kind = "system-component"
	KindParty            Kind = "party"
	KindUser             Kind = "user"
)

// AllKinds lists every subject kind, in the order they're searched.
var AllKinds = []Kind{KindDefinedComponent, KindSystemComponent, KindParty, KindUser}

// ParseKind returns the Kind named by value, if there is one.
func ParseKind(value string) (Kind, bool) {
	for _, kind := range AllKinds {
		if string(kind) == strings.ToLower(strings.TrimSpace(value)) {
			return kind, true
		}
	}
	return "", false
}

// Summary is an entity evidence can name as its subject.
type Summary struct {
	SubjectUUID uuid.UUID `json:"subject-uuid" gorm:"column:subject_uuid"`
	// Type is the OSCAL subject type: component, party or user.
	Type  string `json:"type" gorm:"column:type"`
	Kind  Kind   `json:"kind" gorm:"column:kind"`
	Title string `json:"title" gorm:"column:title"`
	// Context is what the subject belongs to: a defined component's component definition, or
	// a system component's SSP.
	Context *string `json:"context,omitempty" gorm:"column:context"`
	// Identity is a defined component's identity labels: the evidence labels that identify it.
	Identity []IdentityLabel `json:"identity,omitempty" gorm:"-"`
	// LinkedSSPs are the SSP system components a defined component is linked to.
	LinkedSSPs []LinkedSSP `json:"linked-ssps,omitempty" gorm:"-"`
}

// IdentityLabel is one identity label of a defined component.
type IdentityLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// LinkedSSP is an SSP system component linked to a defined component.
type LinkedSSP struct {
	SSPID          uuid.UUID `json:"ssp-id"`
	SSPTitle       string    `json:"ssp-title"`
	ComponentID    uuid.UUID `json:"component-id"`
	ComponentTitle string    `json:"component-title"`
}

type ListParams struct {
	// Search matches titles case-insensitively.
	Search string
	// Kinds limits the kinds listed; empty means all.
	Kinds []Kind
	// SSPID limits system components to one SSP; other kinds are unaffected.
	SSPID *uuid.UUID
	// IDs limits the list to these subjects.
	IDs    []uuid.UUID
	Limit  int
	Offset int
}

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// List returns one page of subjects ordered by title, and the total matching.
func (s *Service) List(params ListParams) ([]Summary, int64, error) {
	union, args := subjectsUnion(params)
	var conditions []string
	if search := strings.TrimSpace(params.Search); search != "" {
		conditions = append(conditions, `LOWER(subjects.title) LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLikePattern(strings.ToLower(search))+"%")
	}
	if len(params.IDs) > 0 {
		conditions = append(conditions, "subjects.subject_uuid IN ?")
		args = append(args, params.IDs)
	}
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}
	from := "FROM (" + union + ") subjects" + where

	var total int64
	if err := s.db.Raw("SELECT COUNT(*) "+from, args...).Scan(&total).Error; err != nil {
		return nil, 0, err
	}

	items := []Summary{}
	pageArgs := append(append([]any{}, args...), params.Limit, params.Offset)
	if err := s.db.Raw(
		"SELECT subjects.subject_uuid, subjects.type, subjects.kind, subjects.title, subjects.context "+
			from+
			" ORDER BY LOWER(subjects.title), subjects.kind, subjects.subject_uuid LIMIT ? OFFSET ?",
		pageArgs...,
	).Scan(&items).Error; err != nil {
		return nil, 0, err
	}

	if err := s.addDefinedComponentDetails(items); err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

// addDefinedComponentDetails fills in the identity labels and linked SSP system components
// of the defined components among items, with one query each.
func (s *Service) addDefinedComponentDetails(items []Summary) error {
	byID := map[uuid.UUID]*Summary{}
	ids := []uuid.UUID{}
	for i := range items {
		if items[i].Kind == KindDefinedComponent {
			byID[items[i].SubjectUUID] = &items[i]
			ids = append(ids, items[i].SubjectUUID)
		}
	}
	if len(ids) == 0 {
		return nil
	}

	var labels []struct {
		DefinedComponentID uuid.UUID `gorm:"column:defined_component_id"`
		Key                string    `gorm:"column:key"`
		Value              string    `gorm:"column:value"`
	}
	if err := s.db.Raw(`
		SELECT defined_component_id, key, value
		FROM component_definition_labels
		WHERE defined_component_id IN ?
		ORDER BY defined_component_id, key, value`, ids,
	).Scan(&labels).Error; err != nil {
		return err
	}
	for _, label := range labels {
		item := byID[label.DefinedComponentID]
		item.Identity = append(item.Identity, IdentityLabel{Key: label.Key, Value: label.Value})
	}

	var links []struct {
		DefinedComponentID uuid.UUID `gorm:"column:defined_component_id"`
		SSPID              uuid.UUID `gorm:"column:ssp_id"`
		SSPTitle           string    `gorm:"column:ssp_title"`
		ComponentID        uuid.UUID `gorm:"column:component_id"`
		ComponentTitle     string    `gorm:"column:component_title"`
	}
	if err := s.db.Raw(`
		SELECT sc.defined_component_id, si.system_security_plan_id AS ssp_id, COALESCE(m.title, '') AS ssp_title,
		  sc.id AS component_id, sc.title AS component_title
		FROM system_components sc
		JOIN system_implementations si ON si.id = sc.system_implementation_id
		LEFT JOIN metadata m
		  ON m.parent_type = 'system_security_plans' AND m.parent_id = si.system_security_plan_id
		WHERE sc.defined_component_id IN ?
		ORDER BY LOWER(COALESCE(m.title, '')), LOWER(sc.title), sc.id`, ids,
	).Scan(&links).Error; err != nil {
		return err
	}
	for _, link := range links {
		item := byID[link.DefinedComponentID]
		item.LinkedSSPs = append(item.LinkedSSPs, LinkedSSP{
			SSPID:          link.SSPID,
			SSPTitle:       link.SSPTitle,
			ComponentID:    link.ComponentID,
			ComponentTitle: link.ComponentTitle,
		})
	}

	return nil
}

// Resolve looks up subjects by ID, returning those found keyed by ID.
func (s *Service) Resolve(ids []uuid.UUID) (map[uuid.UUID]Summary, error) {
	found := make(map[uuid.UUID]Summary, len(ids))
	if len(ids) == 0 {
		return found, nil
	}
	items, _, err := s.List(ListParams{IDs: ids, Limit: len(ids) * len(AllKinds)})
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		found[item.SubjectUUID] = item
	}
	return found, nil
}

// subjectsUnion is one SELECT per requested kind, combined with UNION ALL.
func subjectsUnion(params ListParams) (string, []any) {
	kinds := params.Kinds
	if len(kinds) == 0 {
		kinds = AllKinds
	}

	selects := make([]string, 0, len(kinds))
	var args []any
	for _, kind := range kinds {
		switch kind {
		case KindDefinedComponent:
			selects = append(selects, fmt.Sprintf(`
				SELECT dc.id AS subject_uuid, 'component' AS type, '%s' AS kind, dc.title AS title, m.title AS context
				FROM defined_components dc
				LEFT JOIN metadata m
				  ON m.parent_type = 'component_definitions' AND m.parent_id = dc.component_definition_id`,
				KindDefinedComponent))
		case KindSystemComponent:
			// The inner join keeps to SSP system components: components created from
			// evidence have no system implementation.
			sspFilter := ""
			if params.SSPID != nil {
				sspFilter = " WHERE si.system_security_plan_id = ?"
				args = append(args, *params.SSPID)
			}
			selects = append(selects, fmt.Sprintf(`
				SELECT sc.id AS subject_uuid, 'component' AS type, '%s' AS kind, sc.title AS title, m.title AS context
				FROM system_components sc
				JOIN system_implementations si ON si.id = sc.system_implementation_id
				LEFT JOIN metadata m
				  ON m.parent_type = 'system_security_plans' AND m.parent_id = si.system_security_plan_id%s`,
				KindSystemComponent, sspFilter))
		case KindParty:
			selects = append(selects, fmt.Sprintf(`
				SELECT p.id AS subject_uuid, 'party' AS type, '%s' AS kind,
				  COALESCE(NULLIF(p.name, ''), NULLIF(p.short_name, ''), CAST(p.id AS TEXT)) AS title,
				  NULL AS context
				FROM parties p`,
				KindParty))
		case KindUser:
			// The same users, and the same display name, as /users/select.
			selects = append(selects, fmt.Sprintf(`
				SELECT u.id AS subject_uuid, 'user' AS type, '%s' AS kind,
				  COALESCE(NULLIF(TRIM(TRIM(COALESCE(u.first_name, '')) || ' ' || TRIM(COALESCE(u.last_name, ''))), ''), CAST(u.id AS TEXT)) AS title,
				  NULL AS context
				FROM ccf_users u
				WHERE u.deleted_at IS NULL AND u.is_active = TRUE AND u.is_locked = FALSE`,
				KindUser))
		}
	}

	return strings.Join(selects, " UNION ALL "), args
}

func escapeLikePattern(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}
