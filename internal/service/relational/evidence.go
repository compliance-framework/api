package relational

import (
	"errors"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// EvidenceStatusNotSatisfied is the OSCAL ObjectiveStatus.State value indicating a failed check.
const EvidenceStatusNotSatisfied = "not-satisfied"

// EvidenceStatusSatisfied is the OSCAL ObjectiveStatus.State value indicating a passed check.
const EvidenceStatusSatisfied = "satisfied"

type Evidence struct {
	// ID is the unique ID for this specific observation, and will be used as the primary key in the database.
	UUIDModel

	// UUID needs to remain consistent when automation runs again, but unique for each subject.
	// It represents the "stream" of the same observation being made over time.
	UUID       uuid.UUID                              `gorm:"index:evidence_stream_idx;index:evidence_stream_collected_idx,priority:1" json:"uuid,omitempty"`
	BackMatter *BackMatter                            `gorm:"polymorphic:Parent;" json:"back-matter,omitempty"`
	Signature  *datatypes.JSONType[EvidenceSignature] `json:"signature,omitempty"`

	Title       string  `json:"title"`
	Description string  `json:"description"`
	Remarks     *string `json:"remarks,omitempty"`

	// Assigning labels to Evidence makes it searchable and easily usable in the UI
	Labels []Labels `gorm:"many2many:evidence_labels;" json:"labels"`

	// When did we start collecting the evidence, and when did the process end, and how long is it valid for ?
	Start   time.Time  `json:"start"`
	End     time.Time  `gorm:"index:evidence_stream_collected_idx,priority:2,sort:desc" json:"end"`
	Expires *time.Time `json:"expires,omitempty"`

	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`

	// Who or What is generating this evidence
	Origins datatypes.JSONSlice[Origin] `json:"origins,omitempty"`

	// What steps did we take to create this evidence
	Activities []Activity `gorm:"many2many:evidence_activities" json:"activities,omitempty"`

	InventoryItems []InventoryItem `gorm:"many2many:evidence_inventory_items" json:"inventory-items,omitempty"`

	// Which components of the subject are being observed. A tool, user, policy etc.
	Components []SystemComponent `gorm:"many2many:evidence_components" json:"components,omitempty"`
	// Who or What are we providing evidence for. What's under test.
	Subjects []AssessmentSubject `gorm:"many2many:evidence_subjects;" json:"subjects,omitempty"`

	// Did we satisfy what was being tested for, or did we fail ?
	Status datatypes.JSONType[oscalTypes_1_1_3.ObjectiveStatus] `json:"status"`
}

// StatusCount is one (status-state, distinct-stream-count) row of an evidence
// status rollup. It mirrors the ad-hoc struct in profile_compliance.go so the
// lineage rollups and the profile compliance endpoint speak the same shape.
type StatusCount struct {
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

// evidenceFilterChunkSize bounds how many per-filter subqueries go into one
// UNION ALL statement, keeping any single query's size and parameter count sane.
const evidenceFilterChunkSize = 50

// GetEvidenceStatusCountsByFilters computes latest-evidence status counts for a
// batch of label filters keyed by an opaque id (typically the Filter row UUID),
// so the lineage rollups can resolve every in-scope control's compliance in a
// handful of queries instead of an N+1 of one query per control/filter.
//
// Semantics are identical to profile_compliance.getStatusCountsForFilters: it
// counts DISTINCT evidence streams grouped by status->>'state' over the latest
// evidence in each stream. componentID, when set, further restricts to evidence
// observed on that system component (via evidence_components).
//
// Performance: the latest-per-stream set (the expensive DISTINCT ON scan) is
// computed ONCE per chunk in a MATERIALIZED CTE and reused by every filter's
// UNION ALL branch — versus the old per-filter loop that re-scanned the whole
// evidences table for each filter (O(filters) full scans, seconds-to-minutes on
// real data). Postgres-first: DISTINCT ON + MATERIALIZED are Postgres features.
func GetEvidenceStatusCountsByFilters(db *gorm.DB, filters map[uuid.UUID]labelfilter.Filter, componentID *uuid.UUID) (map[uuid.UUID][]StatusCount, error) {
	result := make(map[uuid.UUID][]StatusCount, len(filters))
	if len(filters) == 0 {
		return result, nil
	}

	ids := make([]uuid.UUID, 0, len(filters))
	for id := range filters {
		ids = append(ids, id)
		result[id] = []StatusCount{} // ensure every filter has an entry, even with zero matches
	}

	for start := 0; start < len(ids); start += evidenceFilterChunkSize {
		end := start + evidenceFilterChunkSize
		if end > len(ids) {
			end = len(ids)
		}

		branches := make([]string, 0, end-start)
		args := make([]any, 0, (end-start)*3)
		for _, id := range ids[start:end] {
			clause := "TRUE"
			if scope := filters[id].Scope; scope != nil {
				sql, sqlArgs, err := labelScopeToSQL(*scope)
				if err != nil {
					return nil, err
				}
				clause = sql
				// filter_id placeholder comes first in the SELECT, then the WHERE args.
				args = append(args, id)
				args = append(args, sqlArgs...)
			} else {
				args = append(args, id)
			}

			branch := "SELECT ?::uuid AS filter_id, l.status->>'state' AS status, count(DISTINCT l.uuid) AS count FROM latest l WHERE (" + clause + ")"
			if componentID != nil {
				branch += " AND EXISTS (SELECT 1 FROM evidence_components ec WHERE ec.evidence_id = l.id AND ec.system_component_id = ?)"
				args = append(args, *componentID)
			}
			branch += " GROUP BY l.status->>'state'"
			branches = append(branches, branch)
		}

		query := `WITH latest AS MATERIALIZED (SELECT DISTINCT ON (uuid) * FROM evidences ORDER BY uuid, "end" DESC) ` +
			strings.Join(branches, " UNION ALL ")

		rows := []struct {
			FilterID uuid.UUID `gorm:"column:filter_id"`
			Status   string    `gorm:"column:status"`
			Count    int64     `gorm:"column:count"`
		}{}
		if err := db.Raw(query, args...).Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			result[r.FilterID] = append(result[r.FilterID], StatusCount{Count: r.Count, Status: r.Status})
		}
	}
	return result, nil
}

// labelScopeToSQL renders a label filter scope into a boolean SQL predicate over
// the `latest l` relation, mirroring getScopeClause but as reusable SQL text so
// many filters can share one materialized latest-stream CTE. Uses `?` placeholders.
func labelScopeToSQL(scope labelfilter.Scope) (string, []any, error) {
	if scope.IsCondition() {
		sql, args := labelConditionToSQL(*scope.Condition)
		return sql, args, nil
	}
	if scope.IsQuery() {
		return labelQueryToSQL(*scope.Query)
	}
	return "TRUE", nil, nil
}

func labelConditionToSQL(condition labelfilter.Condition) (string, []any) {
	exists := "EXISTS (SELECT 1 FROM evidence_labels el WHERE el.evidence_id = l.id AND lower(el.labels_name) = lower(?) AND lower(el.labels_value) = lower(?))"
	args := []any{condition.Label, condition.Value}
	if condition.Operator == "!=" {
		return "NOT " + exists, args
	}
	return exists, args
}

func labelQueryToSQL(query labelfilter.Query) (string, []any, error) {
	op := strings.ToUpper(strings.TrimSpace(query.Operator))
	if op != "AND" && op != "OR" {
		return "", nil, errors.New("unrecognised query operator in label filter")
	}
	parts := make([]string, 0, len(query.Scopes))
	args := make([]any, 0)
	for _, scope := range query.Scopes {
		sql, sqlArgs, err := labelScopeToSQL(scope)
		if err != nil {
			return "", nil, err
		}
		parts = append(parts, "("+sql+")")
		args = append(args, sqlArgs...)
	}
	if len(parts) == 0 {
		return "TRUE", nil, nil
	}
	return "(" + strings.Join(parts, " "+op+" ") + ")", args, nil
}

func GetLatestEvidenceStreamsQuery(db *gorm.DB) *gorm.DB {
	query := db.
		Model(&Evidence{}).
		Select("DISTINCT ON (uuid) *").
		Order("uuid").
		Order("evidences.end desc")
	return query
}

func GetEvidenceSearchByFilterQuery(latestQuery *gorm.DB, db *gorm.DB, filters ...labelfilter.Filter) (*gorm.DB, error) {
	//sql := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
	finalWhere := db.Session(&gorm.Session{})
	finalWhere = finalWhere.Table("(?) as l", latestQuery)

	filterWhere := db.Session(&gorm.Session{})
	hasFilter := false
	for _, filter := range filters {
		if filter.Scope != nil {
			subQuery, err := getScopeClause(db, *filter.Scope)
			if err != nil {
				return nil, err
			}
			if !hasFilter {
				filterWhere = filterWhere.Where(subQuery)
				hasFilter = true
			} else {
				filterWhere = filterWhere.Or(subQuery)
			}
		}
	}
	if hasFilter {
		finalWhere = finalWhere.Where(filterWhere)
	}

	return finalWhere, nil
}

func getScopeClause(db *gorm.DB, scope labelfilter.Scope) (*gorm.DB, error) {
	if scope.IsCondition() {
		return getConditionClause(db, *scope.Condition), nil
	} else if scope.IsQuery() {
		return getQueryClause(db, *scope.Query)
	}
	return db, nil
}

func getQueryClause(db *gorm.DB, query labelfilter.Query) (*gorm.DB, error) {
	var err error
	if strings.ToLower(query.Operator) == "and" {
		sub := db.Session(&gorm.Session{})
		for _, scope := range query.Scopes {
			sc := db.Session(&gorm.Session{})
			sc, err = getScopeClause(sc, scope)
			if err != nil {
				return nil, err
			}
			sub = sub.Where(sc)
		}
		return db.Where(sub), nil
	} else if strings.ToLower(query.Operator) == "or" {
		sub := db.Session(&gorm.Session{})
		for _, scope := range query.Scopes {
			sc := db.Session(&gorm.Session{})
			sc, err = getScopeClause(sc, scope)
			if err != nil {
				return nil, err
			}
			sub = sub.Or(sc)
		}
		return db.Where(sub), nil
	}
	return db, errors.New("unrecognised query operator in label filter")
}

func getConditionClause(db *gorm.DB, condition labelfilter.Condition) *gorm.DB {
	sub := db.Session(&gorm.Session{})
	labelQuery := sub.
		Select("1").
		Table("evidence_labels el").
		Where("el.evidence_id = l.id").
		Where("lower(el.labels_name) = lower(?)", condition.Label).
		Where("lower(el.labels_value) = lower(?)", condition.Value)

	if condition.Operator == "!=" {
		return sub.Not("EXISTS(?)", labelQuery)
	}
	return sub.Where("EXISTS(?)", labelQuery)
}
