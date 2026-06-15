package suggestions

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SuggestionService struct {
	db *gorm.DB
}

func NewSuggestionService(db *gorm.DB) *SuggestionService {
	return &SuggestionService{db: db}
}

type GatherOptions struct {
	MaxComponents       int
	MaxComponentTextLen int
	MaxControlTextLen   int
}

type GatheredInput struct {
	Cell              GridCell             `json:"cell"`
	Controls          []ControlInput       `json:"controls"`
	LabelSets         []LabelSetInput      `json:"label_sets"`
	SystemContext     SystemContextInput   `json:"system_context"`
	LabelKeyDocs      []LabelKeyDocInput   `json:"label_key_docs"`
	Filters           []VisibleFilterInput `json:"filters"`
	SameSSPFilters    []VisibleFilterInput `json:"same_ssp_filters"`
	GlobalFilterNames []string             `json:"global_filter_names"`
	Stats             map[string]int       `json:"stats"`
}

type SystemContextInput struct {
	SystemName  string                 `json:"system_name"`
	Description string                 `json:"description"`
	Components  []SystemComponentInput `json:"components"`
}

type SystemComponentInput struct {
	Title       string `json:"title"`
	Type        string `json:"type"`
	Purpose     string `json:"purpose"`
	Description string `json:"description"`
}

type LabelKeyDocInput struct {
	Key         string `json:"key"`
	Description string `json:"description"`
}

type InsertMappingsResult struct {
	Inserted int
	Excluded int
	Capped   int
}

type ConflictError struct {
	IDs []uuid.UUID
}

func (e *ConflictError) Error() string {
	ids := make([]string, 0, len(e.IDs))
	for _, id := range e.IDs {
		ids = append(ids, id.String())
	}
	return "dashboard suggestions are not pending or do not belong to SSP: " + strings.Join(ids, ", ")
}

func (s *SuggestionService) ResolveScope(sspID uuid.UUID, scope Scope) (Snapshot, error) {
	controls, err := s.resolvedControlKeys(sspID)
	if err != nil {
		return Snapshot{}, err
	}
	labelSets, err := s.currentLabelSetHashes()
	if err != nil {
		return Snapshot{}, err
	}
	return ResolveSnapshot(scope, controls, labelSets)
}

func (s *SuggestionService) GatherLabelSets(hashes []string) ([]LabelSetInput, error) {
	if len(hashes) == 0 {
		return s.gatherAllLabelSets()
	}
	return s.gatherLabelSets(hashes)
}

func (s *SuggestionService) GatherCellInput(sspID uuid.UUID, cell GridCell, opts GatherOptions) (GatheredInput, error) {
	stats := map[string]int{}
	controls, err := s.gatherControls(sspID, cell.ControlKeys, opts)
	if err != nil {
		return GatheredInput{}, err
	}
	labelSets, err := s.gatherLabelSets(cell.LabelSetHashes)
	if err != nil {
		return GatheredInput{}, err
	}
	systemContext, err := s.gatherSystemContext(sspID, opts, stats)
	if err != nil {
		return GatheredInput{}, err
	}
	labelDocs, err := s.gatherLabelKeyDocs()
	if err != nil {
		return GatheredInput{}, err
	}
	filters, sameSSPFilters, globalNames, err := s.gatherVisibleFilters(sspID)
	if err != nil {
		return GatheredInput{}, err
	}
	return GatheredInput{
		Cell:              cell,
		Controls:          controls,
		LabelSets:         labelSets,
		SystemContext:     systemContext,
		LabelKeyDocs:      labelDocs,
		Filters:           filters,
		SameSSPFilters:    sameSSPFilters,
		GlobalFilterNames: globalNames,
		Stats:             stats,
	}, nil
}

func (g GatheredInput) CellInput() CellInput {
	return CellInput{
		Controls:          g.Controls,
		LabelSets:         g.LabelSets,
		VisibleFilters:    g.Filters,
		SameSSPFilters:    g.SameSSPFilters,
		GlobalFilterNames: g.GlobalFilterNames,
	}
}

func (s *SuggestionService) InsertValidatedMappings(runID uuid.UUID, sspID uuid.UUID, promptVersion string, mappings []ValidatedMapping, maxSuggestionsPerRun int) (InsertMappingsResult, error) {
	if maxSuggestionsPerRun <= 0 {
		maxSuggestionsPerRun = DefaultMaxSuggestionsPerRun
	}
	result := InsertMappingsResult{}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var run DashboardSuggestionRun
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND ssp_id = ?", runID, sspID).First(&run).Error; err != nil {
			return err
		}
		capacity := maxSuggestionsPerRun - run.SuggestionCount
		if capacity <= 0 {
			result.Capped = len(mappings)
			return nil
		}

		for _, mapping := range mappings {
			if capacity <= 0 {
				result.Capped++
				continue
			}
			excluded, err := s.mappingExcluded(tx, sspID, promptVersion, mapping)
			if err != nil {
				return err
			}
			if excluded {
				result.Excluded++
				continue
			}
			catalogID, controlID, err := ParseControlKey(mapping.ControlKey)
			if err != nil {
				return err
			}
			suggestion := DashboardSuggestion{
				RunID:              runID,
				SSPID:              sspID,
				ControlCatalogID:   catalogID,
				ControlID:          controlID,
				LabelSet:           labelsToJSONMap(mapping.LabelSet),
				LabelSetHash:       mapping.LabelSetHash,
				TargetFilterID:     mapping.TargetFilterID,
				ProposedFilterName: mapping.ProposedFilterName,
				Reasoning:          mapping.Reasoning,
				Confidence:         mapping.Confidence,
				Status:             DashboardSuggestionStatusPending,
			}
			create := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&suggestion)
			if create.Error != nil {
				return create.Error
			}
			if create.RowsAffected == 0 {
				result.Excluded++
				continue
			}
			result.Inserted++
			capacity--
			if err := tx.Model(&DashboardSuggestionRun{}).
				Where("id = ?", runID).
				UpdateColumn("suggestion_count", gorm.Expr("suggestion_count + 1")).Error; err != nil {
				return err
			}
			if err := createSuggestionEvent(tx, &suggestion, DashboardSuggestionEventTypeSuggestionCreated, nil, datatypes.JSONMap{
				"prompt_version": promptVersion,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}

func (s *SuggestionService) Accept(sspID uuid.UUID, suggestionIDs []uuid.UUID, actorID uuid.UUID) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		suggestions, err := loadPendingSuggestions(tx, sspID, suggestionIDs)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		byHash := map[string][]DashboardSuggestion{}
		for _, suggestion := range suggestions {
			byHash[suggestion.LabelSetHash] = append(byHash[suggestion.LabelSetHash], suggestion)
		}

		for hash, group := range byHash {
			sort.Slice(group, func(i, j int) bool {
				if group[i].Confidence != group[j].Confidence {
					return group[i].Confidence > group[j].Confidence
				}
				if group[i].ProposedFilterName != group[j].ProposedFilterName {
					return group[i].ProposedFilterName < group[j].ProposedFilterName
				}
				return suggestionIDString(group[i]) < suggestionIDString(group[j])
			})
			labels := jsonMapToLabels(group[0].LabelSet)
			filterID, created, err := s.acceptFilterForHash(tx, sspID, hash, labels, group)
			if err != nil {
				return err
			}
			for _, suggestion := range group {
				if err := tx.Exec(`
					INSERT INTO filter_controls (filter_id, control_catalog_id, control_id)
					VALUES (?, ?, ?)
					ON CONFLICT DO NOTHING
				`, filterID, suggestion.ControlCatalogID, suggestion.ControlID).Error; err != nil {
					return err
				}
				if err := tx.Model(&DashboardSuggestion{}).
					Where("id = ?", suggestion.ID).
					Updates(map[string]any{
						"status":             DashboardSuggestionStatusAccepted,
						"accepted_filter_id": filterID,
						"decided_by_user_id": actorID,
						"decided_at":         now,
					}).Error; err != nil {
					return err
				}
				suggestion.Status = DashboardSuggestionStatusAccepted
				suggestion.AcceptedFilterID = &filterID
				suggestion.DecidedByUserID = &actorID
				suggestion.DecidedAt = &now
				payload := datatypes.JSONMap{
					"filter_id":  filterID.String(),
					"created":    created,
					"reasoning":  suggestion.Reasoning,
					"confidence": suggestion.Confidence,
				}
				var run DashboardSuggestionRun
				if err := tx.Select("model", "prompt_version").Where("id = ?", suggestion.RunID).First(&run).Error; err == nil {
					payload["model"] = run.Model
					payload["prompt_version"] = run.PromptVersion
				}
				if err := createSuggestionEvent(tx, &suggestion, DashboardSuggestionEventTypeAccepted, &actorID, payload); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func suggestionIDString(suggestion DashboardSuggestion) string {
	if suggestion.ID == nil {
		return ""
	}
	return suggestion.ID.String()
}

func (s *SuggestionService) Reject(sspID uuid.UUID, suggestionIDs []uuid.UUID, reason string, actorID uuid.UUID) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		suggestions, err := loadPendingSuggestions(tx, sspID, suggestionIDs)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		reason = strings.TrimSpace(reason)
		for _, suggestion := range suggestions {
			if err := tx.Model(&DashboardSuggestion{}).
				Where("id = ?", suggestion.ID).
				Updates(map[string]any{
					"status":             DashboardSuggestionStatusRejected,
					"reject_reason":      reason,
					"decided_by_user_id": actorID,
					"decided_at":         now,
				}).Error; err != nil {
				return err
			}
			suggestion.Status = DashboardSuggestionStatusRejected
			suggestion.RejectReason = &reason
			suggestion.DecidedByUserID = &actorID
			suggestion.DecidedAt = &now
			if err := createSuggestionEvent(tx, &suggestion, DashboardSuggestionEventTypeRejected, &actorID, datatypes.JSONMap{
				"reason": reason,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SuggestionService) acceptFilterForHash(tx *gorm.DB, sspID uuid.UUID, hash string, labels map[string]string, group []DashboardSuggestion) (uuid.UUID, bool, error) {
	if err := lockAcceptFilterHash(tx, sspID, hash); err != nil {
		return uuid.Nil, false, err
	}

	for _, suggestion := range group {
		if suggestion.TargetFilterID == nil {
			continue
		}
		filter, ok, err := loadSameSSPFilterWithHash(tx, sspID, *suggestion.TargetFilterID, hash)
		if err != nil {
			return uuid.Nil, false, err
		}
		if ok {
			return *filter.ID, false, nil
		}
	}

	var filters []relational.Filter
	if err := tx.Where("ssp_id = ?", sspID).Order("name ASC, id ASC").Find(&filters).Error; err != nil {
		return uuid.Nil, false, err
	}
	for _, filter := range filters {
		filterLabels, ok := CanonicalizeFilter(filter.Filter.Data())
		if ok && CanonicalLabelSetHash(filterLabels) == hash {
			return *filter.ID, false, nil
		}
	}

	name := group[0].ProposedFilterName
	if strings.TrimSpace(name) == "" {
		name = fallbackFilterName(labels)
	}
	filter := relational.Filter{
		Name:   name,
		SSPID:  &sspID,
		Filter: datatypes.NewJSONType(BuildLabelFilter(labels)),
	}
	if err := tx.Create(&filter).Error; err != nil {
		return uuid.Nil, false, err
	}
	return *filter.ID, true, nil
}

func lockAcceptFilterHash(tx *gorm.DB, sspID uuid.UUID, hash string) error {
	if tx.Name() != "postgres" {
		return nil
	}

	sum := sha256.Sum256([]byte(sspID.String() + ":" + hash))
	key1 := int32(binary.BigEndian.Uint32(sum[0:4]))
	key2 := int32(binary.BigEndian.Uint32(sum[4:8]))
	return tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", key1, key2).Error
}

func loadPendingSuggestions(tx *gorm.DB, sspID uuid.UUID, ids []uuid.UUID) ([]DashboardSuggestion, error) {
	var suggestions []DashboardSuggestion
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id IN ?", ids).
		Find(&suggestions).Error; err != nil {
		return nil, err
	}
	found := map[uuid.UUID]DashboardSuggestion{}
	for _, suggestion := range suggestions {
		found[*suggestion.ID] = suggestion
	}
	offending := make([]uuid.UUID, 0)
	for _, id := range ids {
		suggestion, ok := found[id]
		if !ok || suggestion.SSPID != sspID || suggestion.Status != DashboardSuggestionStatusPending {
			offending = append(offending, id)
		}
	}
	if len(offending) > 0 {
		return nil, &ConflictError{IDs: offending}
	}
	return suggestions, nil
}

func loadSameSSPFilterWithHash(tx *gorm.DB, sspID uuid.UUID, filterID uuid.UUID, hash string) (relational.Filter, bool, error) {
	var filter relational.Filter
	err := tx.Where("id = ? AND ssp_id = ?", filterID, sspID).First(&filter).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return relational.Filter{}, false, nil
	}
	if err != nil {
		return relational.Filter{}, false, err
	}
	labels, ok := CanonicalizeFilter(filter.Filter.Data())
	if !ok || CanonicalLabelSetHash(labels) != hash {
		return relational.Filter{}, false, nil
	}
	return filter, true, nil
}

func (s *SuggestionService) mappingExcluded(tx *gorm.DB, sspID uuid.UUID, promptVersion string, mapping ValidatedMapping) (bool, error) {
	catalogID, controlID, err := ParseControlKey(mapping.ControlKey)
	if err != nil {
		return false, err
	}
	var existingCount int64
	if err := tx.Model(&DashboardSuggestion{}).
		Joins("JOIN dashboard_suggestion_runs ON dashboard_suggestion_runs.id = dashboard_suggestions.run_id").
		Where("dashboard_suggestions.ssp_id = ? AND control_catalog_id = ? AND control_id = ? AND label_set_hash = ?", sspID, catalogID, controlID, mapping.LabelSetHash).
		Where("(dashboard_suggestions.status = ? OR (dashboard_suggestions.status = ? AND dashboard_suggestion_runs.prompt_version = ?))", DashboardSuggestionStatusAccepted, DashboardSuggestionStatusRejected, promptVersion).
		Count(&existingCount).Error; err != nil {
		return false, err
	}
	if existingCount > 0 {
		return true, nil
	}

	var filters []relational.Filter
	if err := tx.
		Joins("JOIN filter_controls ON filter_controls.filter_id = filters.id").
		Where("(filters.ssp_id IS NULL OR filters.ssp_id = ?) AND filter_controls.control_catalog_id = ? AND filter_controls.control_id = ?", sspID, catalogID, controlID).
		Group("filters.id").
		Find(&filters).Error; err != nil {
		return false, err
	}
	for _, filter := range filters {
		labels, ok := CanonicalizeFilter(filter.Filter.Data())
		if ok && CanonicalLabelSetHash(labels) == mapping.LabelSetHash {
			return true, nil
		}
	}
	return false, nil
}

func createSuggestionEvent(tx *gorm.DB, suggestion *DashboardSuggestion, eventType DashboardSuggestionEventType, actorID *uuid.UUID, payload datatypes.JSONMap) error {
	snapshot, err := suggestionSnapshot(suggestion)
	if err != nil {
		return err
	}
	event := DashboardSuggestionEvent{
		RunID:        &suggestion.RunID,
		SuggestionID: suggestion.ID,
		EventType:    string(eventType),
		ActorUserID:  actorID,
		OccurredAt:   time.Now().UTC(),
		Payload:      payload,
		Snapshot:     snapshot,
	}
	return tx.Create(&event).Error
}

func suggestionSnapshot(suggestion *DashboardSuggestion) (datatypes.JSONMap, error) {
	raw, err := json.Marshal(suggestion)
	if err != nil {
		return nil, err
	}
	var snapshot datatypes.JSONMap
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func selectDimension(requested []string, all []string, allSet map[string]struct{}) ([]string, []string) {
	if len(requested) == 0 {
		return append([]string(nil), all...), nil
	}
	selectedSet := map[string]struct{}{}
	unknown := make([]string, 0)
	for _, value := range requested {
		value = strings.TrimSpace(value)
		if _, ok := allSet[value]; !ok {
			unknown = append(unknown, value)
			continue
		}
		selectedSet[value] = struct{}{}
	}
	sort.Strings(unknown)
	selected := make([]string, 0, len(selectedSet))
	for _, value := range all {
		if _, ok := selectedSet[value]; ok {
			selected = append(selected, value)
		}
	}
	return selected, unknown
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func labelsToJSONMap(labels map[string]string) datatypes.JSONMap {
	out := datatypes.JSONMap{}
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func jsonMapToLabels(labels datatypes.JSONMap) map[string]string {
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = fmt.Sprint(value)
	}
	return out
}
