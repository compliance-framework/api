package relational

import (
	"errors"
	"sort"
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

// EvidenceStatusCountsForFilters counts DISTINCT evidence streams grouped by status
// state over the latest evidence in each stream, for the given label filters. It is
// the neutral home of the logic oscal.getStatusCountsForFilters used to own inline —
// hoisted here (its natural home: the StatusCount comment above already notes it
// mirrors profile_compliance.go) so both the compliance endpoint and the leverage
// package can share one definition without an import cycle. Empty filters yield an
// empty (non-nil) slice, never a full-table scan.
func EvidenceStatusCountsForFilters(db *gorm.DB, filters []labelfilter.Filter) ([]StatusCount, error) {
	if len(filters) == 0 {
		return []StatusCount{}, nil
	}

	latestQuery := db.Session(&gorm.Session{})
	latestQuery = GetLatestEvidenceStreamsQuery(latestQuery)
	query, err := GetEvidenceSearchByFilterQuery(latestQuery, db, filters...)
	if err != nil {
		return nil, err
	}

	rows := []StatusCount{}
	if err := query.Model(&Evidence{}).
		Select("count(DISTINCT uuid) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Status < rows[j].Status
	})

	return rows, nil
}

// CollapseEvidenceStatus reduces a set of evidence status counts to a single control
// posture: not-satisfied wins over satisfied wins over unknown, case/space-folded,
// with zero-count rows ignored. It is the neutral home of the logic
// oscal.computeProfileControlStatus used to own inline — shared with the leverage
// package's per-responsibility posture so both surfaces collapse identically.
func CollapseEvidenceStatus(rows []StatusCount) string {
	hasSatisfied := false
	for _, row := range rows {
		if row.Count <= 0 {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(row.Status)) {
		case "not-satisfied":
			return "not-satisfied"
		case "satisfied":
			hasSatisfied = true
		}
	}

	if hasSatisfied {
		return "satisfied"
	}

	return "unknown"
}

// latestEvidenceStreamsCTE builds the "latest evidence per stream" set as a
// MATERIALIZED CTE named `latest(id, uuid, state)` using a loose index scan:
// distinct stream uuids + a lateral pick of the most-recent row per uuid over the
// (uuid, "end" DESC) index. This avoids sorting the entire evidences table (a
// DISTINCT ON * over hundreds of thousands of rows spills to disk and costs ~1s+).
// componentID, when set, restricts to streams observed on that system component.
func latestEvidenceStreamsCTE(componentID *uuid.UUID) (string, []any) {
	componentFilter := ""
	var args []any
	if componentID != nil {
		componentFilter = "WHERE EXISTS (SELECT 1 FROM evidence_components ec WHERE ec.evidence_id = l.id AND ec.system_component_id = ?)"
		args = append(args, *componentID)
	}
	cte := `WITH latest AS MATERIALIZED (
		SELECT l.id, u.uuid, l.title, l.status, l.collected, l.expires
		FROM (SELECT DISTINCT uuid FROM evidences) u
		CROSS JOIN LATERAL (
			SELECT e.id, e.title, e.status, e."end" AS collected, e.expires
			FROM evidences e WHERE e.uuid = u.uuid ORDER BY e."end" DESC LIMIT 1
		) l
		` + componentFilter + `
	)`
	return cte, args
}

// LatestEvidenceStream is the most-recent evidence in one stream plus its
// normalized labels, the unit lineage compliance is evaluated over in memory.
type LatestEvidenceStream struct {
	// ID is the latest evidence record's primary key (for deep-linking to
	// GET /evidence/{id}); UUID is the stream identifier.
	ID        uuid.UUID
	UUID      uuid.UUID
	Title     string
	State     string
	Reason    string
	Collected time.Time
	Expires   *time.Time
	Labels    map[string][]string
}

// LoadLatestEvidenceStreams loads the latest evidence per stream (loose index
// scan) with its labels, in a single query. componentID, when set, restricts to
// streams observed on that system component. Postgres-first.
func LoadLatestEvidenceStreams(db *gorm.DB, componentID *uuid.UUID) ([]LatestEvidenceStream, error) {
	cte, args := latestEvidenceStreamsCTE(componentID)
	query := cte + `
		SELECT l.id AS id, l.uuid AS uuid, l.title AS title, l.status->>'state' AS state,
		       l.status->>'reason' AS reason, l.collected AS collected, l.expires AS expires,
		       el.labels_name AS name, el.labels_value AS value
		FROM latest l LEFT JOIN evidence_labels el ON el.evidence_id = l.id`

	rows := []struct {
		ID        uuid.UUID  `gorm:"column:id"`
		UUID      uuid.UUID  `gorm:"column:uuid"`
		Title     string     `gorm:"column:title"`
		State     string     `gorm:"column:state"`
		Reason    string     `gorm:"column:reason"`
		Collected time.Time  `gorm:"column:collected"`
		Expires   *time.Time `gorm:"column:expires"`
		Name      *string    `gorm:"column:name"`
		Value     *string    `gorm:"column:value"`
	}{}
	if err := db.Raw(query, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}

	byUUID := map[uuid.UUID]*LatestEvidenceStream{}
	order := make([]uuid.UUID, 0)
	for _, r := range rows {
		s := byUUID[r.UUID]
		if s == nil {
			s = &LatestEvidenceStream{
				ID: r.ID, UUID: r.UUID, Title: r.Title, State: r.State, Reason: r.Reason,
				Collected: r.Collected, Expires: r.Expires, Labels: map[string][]string{},
			}
			byUUID[r.UUID] = s
			order = append(order, r.UUID)
		}
		if r.Name != nil {
			key := strings.ToLower(strings.TrimSpace(*r.Name))
			if key == "" {
				continue
			}
			val := ""
			if r.Value != nil {
				val = strings.ToLower(strings.TrimSpace(*r.Value))
			}
			s.Labels[key] = append(s.Labels[key], val)
		}
	}

	streams := make([]LatestEvidenceStream, 0, len(order))
	for _, id := range order {
		streams = append(streams, *byUUID[id])
	}
	return streams, nil
}

// GetEvidenceStatusCountsByFilters computes latest-evidence status counts for a
// batch of label filters keyed by an opaque id (typically the Filter row UUID),
// so the lineage rollups can resolve every in-scope control's compliance without
// an N+1 of one query per control/filter.
//
// Semantics match profile_compliance.getStatusCountsForFilters: it counts DISTINCT
// evidence streams grouped by status state over the latest evidence in each stream.
// componentID, when set, restricts to evidence observed on that system component.
//
// Performance: rather than run one label-scoped SQL aggregation per filter (which
// re-derives the latest-per-stream set every time — O(filters) full scans, tens of
// seconds on real data), this loads the latest streams and their labels ONCE and
// evaluates every filter in memory via labelfilter.MatchLabels (whose semantics
// mirror the SQL evaluator). That collapses the DB work to a single query and keeps
// the per-filter cost to cheap in-Go boolean checks. Postgres-first (loose index
// scan + MATERIALIZED CTE).
func GetEvidenceStatusCountsByFilters(db *gorm.DB, filters map[uuid.UUID]labelfilter.Filter, componentID *uuid.UUID) (map[uuid.UUID][]StatusCount, error) {
	result := make(map[uuid.UUID][]StatusCount, len(filters))
	if len(filters) == 0 {
		return result, nil
	}
	for id := range filters {
		result[id] = []StatusCount{} // ensure every filter has an entry, even with zero matches
	}

	streams, err := LoadLatestEvidenceStreams(db, componentID)
	if err != nil {
		return nil, err
	}

	// Evaluate every filter against every latest stream in memory. Each stream is
	// one distinct uuid, so a matching stream is one distinct-stream count.
	for id, filter := range filters {
		counts := map[string]int64{}
		for i := range streams {
			match, err := labelfilter.MatchLabels(filter.Scope, streams[i].Labels)
			if err != nil {
				return nil, err
			}
			if match {
				counts[streams[i].State]++
			}
		}
		sc := make([]StatusCount, 0, len(counts))
		for state, c := range counts {
			sc = append(sc, StatusCount{Count: c, Status: state})
		}
		result[id] = sc
	}
	return result, nil
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
