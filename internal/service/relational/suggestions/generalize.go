package suggestions

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// GeneralizationRunInput carries the run-level settings for a generalization
// (filter-merge) run, which produces suggestion rows deterministically with no
// LLM cells.
type GeneralizationRunInput struct {
	Model                  string
	PromptVersion          string
	GeneralizableLabelKeys []string
	MinSharedControls      int
	MaxSuggestionsPerRun   int
	ActorID                *uuid.UUID
}

// GenerateGeneralizations runs the deterministic filter-merge detector for an
// SSP and, when it finds candidates, creates a completed run holding one pending
// suggestion per merged control. It surfaces in the same pending list as
// LLM-generated suggestions. The run is created already completed (no cells, no
// LLM), so it never holds the single-active-run slot.
func (s *SuggestionService) GenerateGeneralizations(sspID uuid.UUID, input GeneralizationRunInput) (DashboardSuggestionRun, InsertMappingsResult, int, error) {
	candidates, err := s.GatherGeneralizationCandidates(sspID, input.GeneralizableLabelKeys, input.MinSharedControls)
	if err != nil {
		return DashboardSuggestionRun{}, InsertMappingsResult{}, 0, err
	}

	var run DashboardSuggestionRun
	var result InsertMappingsResult
	err = s.db.Transaction(func(tx *gorm.DB) error {
		runID := uuid.New()
		now := time.Now().UTC()
		run = DashboardSuggestionRun{
			UUIDModel:         relational.UUIDModel{ID: &runID},
			SSPID:             sspID,
			Status:            "completed",
			Model:             input.Model,
			PromptVersion:     input.PromptVersion,
			Scope:             datatypes.JSONMap{"controlKeys": []string{}, "labelSetHashes": []string{}, "generalization": true},
			PlannedCalls:      0,
			TriggeredByUserID: input.ActorID,
			StartedAt:         &now,
			CompletedAt:       &now,
			Stats:             datatypes.JSONMap{"generalization_candidates": len(candidates)},
		}
		if err := tx.Create(&run).Error; err != nil {
			return err
		}
		if len(candidates) > 0 {
			result, err = s.InsertGeneralizationCandidatesTx(tx, runID, sspID, input.PromptVersion, candidates)
			if err != nil {
				return err
			}
		}
		if err := CreateRunEventTx(tx, &run, DashboardSuggestionEventTypeRunCompleted, datatypes.JSONMap{
			"generalization_candidates": len(candidates),
			"suggestions_inserted":      result.Inserted,
		}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return DashboardSuggestionRun{}, InsertMappingsResult{}, 0, err
	}
	return run, result, len(candidates), nil
}

// ControlRef identifies a control attached to a filter. CatalogID is the text
// form stored in filter_controls (the join-table uuid/text mismatch invariant);
// ControlID keeps its catalog-canonical casing.
type ControlRef struct {
	CatalogID string
	ControlID string
}

// foldKey case-folds a control reference for set membership, honouring the
// control-id casing invariant (match via UPPER) without mutating the stored
// canonical casing.
func (c ControlRef) foldKey() string {
	return strings.ToLower(strings.TrimSpace(c.CatalogID)) + ":" + strings.ToUpper(strings.TrimSpace(c.ControlID))
}

// FilterWithControls is one SSP-bound filter, its canonical label set, and the
// controls currently attached to it. It is the deterministic input to the
// filter-merge detector.
type FilterWithControls struct {
	ID       uuid.UUID
	Name     string
	Labels   map[string]string
	Controls []ControlRef
}

// GeneralizationCandidate is a proposed merge of several near-duplicate filters
// that differ only by one generalizable label. GeneralizedLabels (G) is the
// common subset with the dropped key removed; Controls is the union of the
// source filters' controls, which the merged filter G will carry.
type GeneralizationCandidate struct {
	DroppedKey        string
	GeneralizedLabels map[string]string
	SourceFilterIDs   []uuid.UUID
	Controls          []ControlRef
}

// DetectGeneralizations finds groups of filters whose label sets are identical
// after removing exactly one generalizable key. It never drops meaning-bearing
// keys (only keys in generalizableKeys are considered) and only proposes a merge
// when the candidate filters share at least minShared controls, so generalizing
// reflects the same control intent across instances. The result is
// deterministic (sorted) and contains no LLM involvement.
func DetectGeneralizations(filters []FilterWithControls, generalizableKeys []string, minShared int) []GeneralizationCandidate {
	if minShared < 1 {
		minShared = 1
	}
	genSet := make(map[string]struct{}, len(generalizableKeys))
	for _, key := range generalizableKeys {
		key = strings.ToLower(strings.TrimSpace(key))
		// Meaning-bearing keys must never be generalized away.
		if key == "" || key == "_policy" || key == "type" {
			continue
		}
		genSet[key] = struct{}{}
	}

	// Index filters by full canonical hash so a filter that omits the dropped key
	// (and therefore already equals the generalized form) can join the group.
	byFullHash := map[string][]FilterWithControls{}
	for _, filter := range filters {
		if len(filter.Labels) == 0 {
			continue
		}
		byFullHash[CanonicalLabelSetHash(filter.Labels)] = append(byFullHash[CanonicalLabelSetHash(filter.Labels)], filter)
	}

	type groupKey struct {
		key string
		sig string
	}
	groups := map[groupKey][]FilterWithControls{}
	order := make([]groupKey, 0)
	for _, filter := range filters {
		if len(filter.Labels) == 0 {
			continue
		}
		for key := range filter.Labels {
			lowerKey := strings.ToLower(key)
			if _, ok := genSet[lowerKey]; !ok {
				continue
			}
			reduced := make(map[string]string, len(filter.Labels))
			for k, v := range filter.Labels {
				if strings.ToLower(k) == lowerKey {
					continue
				}
				reduced[k] = v
			}
			// Never merge into a match-everything filter.
			if len(reduced) == 0 {
				continue
			}
			gk := groupKey{key: lowerKey, sig: CanonicalLabelSetHash(reduced)}
			if _, seen := groups[gk]; !seen {
				order = append(order, gk)
			}
			groups[gk] = append(groups[gk], filter)
		}
	}

	candidates := make([]GeneralizationCandidate, 0)
	for _, gk := range order {
		members := groups[gk]
		// Include any filter that omits the dropped key but already equals the
		// generalized form (its full hash == the reduced signature).
		seenIDs := map[uuid.UUID]struct{}{}
		for _, m := range members {
			seenIDs[m.ID] = struct{}{}
		}
		for _, omit := range byFullHash[gk.sig] {
			if _, ok := omit.Labels[gk.key]; ok {
				continue
			}
			if _, dup := seenIDs[omit.ID]; dup {
				continue
			}
			seenIDs[omit.ID] = struct{}{}
			members = append(members, omit)
		}

		members = dedupeFilters(members)
		if len(members) < 2 {
			continue
		}

		shared := sharedControlCount(members)
		if shared < minShared {
			continue
		}

		// Generalized labels G = the common subset (the dropped key removed),
		// reconstructed from the first member so casing is preserved.
		generalized := make(map[string]string, len(members[0].Labels))
		for k, v := range members[0].Labels {
			if strings.ToLower(k) == gk.key {
				continue
			}
			generalized[k] = v
		}
		if len(generalized) == 0 {
			continue
		}

		ids := make([]uuid.UUID, 0, len(members))
		for _, m := range members {
			ids = append(ids, m.ID)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })

		candidates = append(candidates, GeneralizationCandidate{
			DroppedKey:        gk.key,
			GeneralizedLabels: generalized,
			SourceFilterIDs:   ids,
			Controls:          unionControls(members),
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].DroppedKey != candidates[j].DroppedKey {
			return candidates[i].DroppedKey < candidates[j].DroppedKey
		}
		return CanonicalLabelSetHash(candidates[i].GeneralizedLabels) < CanonicalLabelSetHash(candidates[j].GeneralizedLabels)
	})
	return candidates
}

func dedupeFilters(filters []FilterWithControls) []FilterWithControls {
	seen := map[uuid.UUID]struct{}{}
	out := make([]FilterWithControls, 0, len(filters))
	for _, f := range filters {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		out = append(out, f)
	}
	return out
}

// sharedControlCount returns how many controls appear in every member filter.
func sharedControlCount(members []FilterWithControls) int {
	if len(members) == 0 {
		return 0
	}
	counts := map[string]int{}
	for _, member := range members {
		seen := map[string]struct{}{}
		for _, control := range member.Controls {
			key := control.foldKey()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			counts[key]++
		}
	}
	shared := 0
	for _, count := range counts {
		if count == len(members) {
			shared++
		}
	}
	return shared
}

// unionControls returns the deduped union of every member's controls, keeping
// the first-seen catalog-canonical casing and sorted for stable emission.
func unionControls(members []FilterWithControls) []ControlRef {
	seen := map[string]ControlRef{}
	for _, member := range members {
		for _, control := range member.Controls {
			key := control.foldKey()
			if _, ok := seen[key]; !ok {
				seen[key] = control
			}
		}
	}
	out := make([]ControlRef, 0, len(seen))
	for _, control := range seen {
		out = append(out, control)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].foldKey() < out[j].foldKey() })
	return out
}

// GatherGeneralizationCandidates loads this SSP's filters and their attached
// controls, then runs the deterministic merge detector.
func (s *SuggestionService) GatherGeneralizationCandidates(sspID uuid.UUID, generalizableKeys []string, minShared int) ([]GeneralizationCandidate, error) {
	var filters []relational.Filter
	if err := s.db.Where("ssp_id = ?", sspID).Order("name ASC, id ASC").Find(&filters).Error; err != nil {
		return nil, err
	}
	if len(filters) == 0 {
		return nil, nil
	}

	ids := make([]uuid.UUID, 0, len(filters))
	for _, filter := range filters {
		ids = append(ids, *filter.ID)
	}
	var controlRows []struct {
		FilterID  uuid.UUID `gorm:"column:filter_id"`
		CatalogID string    `gorm:"column:control_catalog_id"`
		ControlID string    `gorm:"column:control_id"`
	}
	if err := s.db.
		Table("filter_controls").
		Select("filter_id, control_catalog_id, control_id").
		Where("filter_id IN ?", ids).
		Scan(&controlRows).Error; err != nil {
		return nil, err
	}
	controlsByFilter := map[uuid.UUID][]ControlRef{}
	for _, row := range controlRows {
		controlsByFilter[row.FilterID] = append(controlsByFilter[row.FilterID], ControlRef{CatalogID: row.CatalogID, ControlID: row.ControlID})
	}

	inputs := make([]FilterWithControls, 0, len(filters))
	for _, filter := range filters {
		labels, ok := CanonicalizeFilter(filter.Filter.Data())
		if !ok || len(labels) == 0 {
			continue
		}
		inputs = append(inputs, FilterWithControls{
			ID:       *filter.ID,
			Name:     filter.Name,
			Labels:   labels,
			Controls: controlsByFilter[*filter.ID],
		})
	}
	return DetectGeneralizations(inputs, generalizableKeys, minShared), nil
}

// InsertGeneralizationCandidatesTx inserts one suggestion row per control in the
// union of each candidate's source filters, tagged as a generalization with the
// source filter IDs recorded. Rows reuse the existing dedup so an already-merged
// control is skipped. Returns the number of rows inserted.
func (s *SuggestionService) InsertGeneralizationCandidatesTx(tx *gorm.DB, runID uuid.UUID, sspID uuid.UUID, promptVersion string, candidates []GeneralizationCandidate) (InsertMappingsResult, error) {
	result := InsertMappingsResult{}
	for _, candidate := range candidates {
		labels := candidate.GeneralizedLabels
		if len(labels) == 0 {
			continue
		}
		filterHash := CanonicalLabelSetHash(labels)
		labelMap := labelsToJSONMap(labels)
		for _, control := range candidate.Controls {
			catalogID, err := uuid.Parse(strings.TrimSpace(control.CatalogID))
			if err != nil {
				// filter_controls keeps catalog ids as text; skip rows that are not
				// parseable uuids rather than failing the whole merge.
				result.Excluded++
				continue
			}
			mapping := ValidatedMapping{
				ControlKey:             ControlKey(catalogID, control.ControlID),
				LabelSetHash:           filterHash,
				LabelSet:               labels,
				ProposedFilterLabelSet: labels,
				Action:                 MappingActionNewFilter,
				Confidence:             1,
				Reasoning:              generalizationReasoning(candidate),
			}
			excluded, err := s.mappingExcluded(tx, sspID, promptVersion, mapping)
			if err != nil {
				return result, err
			}
			if excluded {
				result.Excluded++
				continue
			}
			suggestion := DashboardSuggestion{
				RunID:                  runID,
				SSPID:                  sspID,
				ControlCatalogID:       catalogID,
				ControlID:              control.ControlID,
				LabelSet:               labelMap,
				LabelSetHash:           filterHash,
				ProposedFilterLabelSet: labelMap,
				ProposedFilterName:     fallbackFilterName(labels),
				Reasoning:              mapping.Reasoning,
				Confidence:             1,
				Status:                 DashboardSuggestionStatusPending,
				IsGeneralization:       true,
				SourceFilterIDs:        datatypes.NewJSONSlice(candidate.SourceFilterIDs),
			}
			create := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&suggestion)
			if create.Error != nil {
				return result, create.Error
			}
			if create.RowsAffected == 0 {
				result.Excluded++
				continue
			}
			result.Inserted++
			if err := tx.Model(&DashboardSuggestionRun{}).
				Where("id = ?", runID).
				UpdateColumn("suggestion_count", gorm.Expr("suggestion_count + 1")).Error; err != nil {
				return result, err
			}
			if err := createSuggestionEvent(tx, &suggestion, DashboardSuggestionEventTypeSuggestionCreated, nil, datatypes.JSONMap{
				"prompt_version": promptVersion,
				"generalization": true,
			}); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func generalizationReasoning(candidate GeneralizationCandidate) string {
	return "Merges " + plural(len(candidate.SourceFilterIDs), "filter") +
		" that differ only by the \"" + candidate.DroppedKey +
		"\" label into one generalized filter that drops it."
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
