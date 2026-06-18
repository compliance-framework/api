package suggestions

import (
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// EditGroupInput describes a user edit to a group of pending suggestions that
// share one proposed-filter label set (one UI card). Labels are a full
// replacement set; AddControlKeys/RemoveIDs adjust group membership.
type EditGroupInput struct {
	IDs                []uuid.UUID
	ProposedFilterName *string
	Labels             *map[string]string
	AddControlKeys     []string
	RemoveIDs          []uuid.UUID
}

// EditValidationError is returned when an edit request is structurally invalid
// (e.g. the IDs do not form a single group, or the resulting label set is empty).
type EditValidationError struct {
	Message string
}

func (e *EditValidationError) Error() string { return e.Message }

// EditGroup applies a user edit to a pending suggestion group and returns the
// IDs of the resulting pending suggestions. The proposed filter labels are
// written verbatim (the subset-of-evidence rule is intentionally bypassed for
// human overrides); edited rows are flagged. Accept reads the stored labels, so
// no Accept-path change is needed.
func (s *SuggestionService) EditGroup(sspID uuid.UUID, in EditGroupInput, actorID uuid.UUID) ([]uuid.UUID, error) {
	var resultIDs []uuid.UUID
	err := s.db.Transaction(func(tx *gorm.DB) error {
		members, err := loadPendingSuggestions(tx, sspID, in.IDs)
		if err != nil {
			return err
		}
		if len(members) == 0 {
			return &EditValidationError{Message: "no suggestions to edit"}
		}

		// All members must currently share one proposed-filter hash (one group).
		oldHash := CanonicalLabelSetHash(suggestionFilterLabels(members[0]))
		for _, member := range members[1:] {
			if CanonicalLabelSetHash(suggestionFilterLabels(member)) != oldHash {
				return &EditValidationError{Message: "the selected suggestions do not form a single filter group"}
			}
		}

		memberIDs := make(map[uuid.UUID]struct{}, len(members))
		for _, member := range members {
			memberIDs[*member.ID] = struct{}{}
		}
		removeSet := make(map[uuid.UUID]struct{}, len(in.RemoveIDs))
		for _, id := range in.RemoveIDs {
			if _, ok := memberIDs[id]; !ok {
				return &EditValidationError{Message: "cannot remove a suggestion that is not part of the group"}
			}
			removeSet[id] = struct{}{}
		}

		// Resolve the post-edit label set and name (the group's new identity).
		newLabels := suggestionFilterLabels(members[0])
		labelsChanged := false
		if in.Labels != nil {
			normalized, err := normalizeEditedLabels(*in.Labels)
			if err != nil {
				return err
			}
			if len(normalized) == 0 {
				return &EditValidationError{Message: "proposed filter labels cannot be empty"}
			}
			newLabels = normalized
			labelsChanged = true
		}
		newHash := CanonicalLabelSetHash(newLabels)

		newName := members[0].ProposedFilterName
		if in.ProposedFilterName != nil {
			if trimmed := strings.TrimSpace(*in.ProposedFilterName); trimmed != "" {
				newName, _ = truncateRunes(trimmed, 120, "")
			}
		}

		// Serialize against concurrent accept/edit converging on the same filter.
		if err := lockAcceptFilterHash(tx, sspID, newHash); err != nil {
			return err
		}

		now := time.Now().UTC()
		basePayload := datatypes.JSONMap{
			"old_proposed_filter_label_set": members[0].ProposedFilterLabelSet,
			"new_proposed_filter_label_set": labelsToJSONMap(newLabels),
			"old_proposed_filter_name":      members[0].ProposedFilterName,
			"new_proposed_filter_name":      newName,
		}

		// When relabelling, ensure no kept member would collide with a different
		// pending suggestion under the unique (ssp, control, proposed labels) index.
		if labelsChanged && newHash != oldHash {
			for _, member := range members {
				if _, removed := removeSet[*member.ID]; removed {
					continue
				}
				conflict, err := s.pendingFilterLabelConflict(tx, sspID, member, newHash, memberIDs)
				if err != nil {
					return err
				}
				if conflict {
					return &EditValidationError{Message: "the edited labels duplicate an existing pending suggestion for control " + member.ControlID}
				}
			}
		}

		// Cumulative list of control IDs removed from this group across edits,
		// mirrored onto every surviving row so the card can render them struck-out.
		removedControlIDs, err := computeRemovedControlIDs(members, removeSet, in.AddControlKeys)
		if err != nil {
			return err
		}
		removedSlice := datatypes.NewJSONSlice(removedControlIDs)

		for _, member := range members {
			if _, removed := removeSet[*member.ID]; removed {
				if err := s.rejectEditedMember(tx, member, actorID, now, basePayload); err != nil {
					return err
				}
				continue
			}
			updates := map[string]any{
				"is_user_edited":       true,
				"edited_by_user_id":    actorID,
				"edited_at":            now,
				"proposed_filter_name": newName,
				"removed_control_ids":  removedSlice,
			}
			if labelsChanged {
				updates["proposed_filter_label_set"] = labelsToJSONMap(newLabels)
			}
			// Capture the AI baseline once, on the first edit of an AI-generated row,
			// so the diff always compares against the original proposal.
			if !member.AddedByUser && len(member.OriginalProposedFilterLabelSet) == 0 {
				updates["original_proposed_filter_label_set"] = labelsToJSONMap(suggestionFilterLabels(member))
				if member.OriginalProposedFilterName == nil {
					updates["original_proposed_filter_name"] = member.ProposedFilterName
				}
			}
			if err := tx.Model(&DashboardSuggestion{}).Where("id = ?", member.ID).Updates(updates).Error; err != nil {
				return err
			}
			member.ProposedFilterLabelSet = labelsToJSONMap(newLabels)
			member.ProposedFilterName = newName
			member.IsUserEdited = true
			member.EditedByUserID = &actorID
			member.EditedAt = &now
			if err := createSuggestionEvent(tx, &member, DashboardSuggestionEventTypeEdited, &actorID, basePayload); err != nil {
				return err
			}
			resultIDs = append(resultIDs, *member.ID)
		}

		// Added controls become new pending rows carrying the edited labels/name.
		added, err := s.addEditedControls(tx, sspID, members[0].RunID, in.AddControlKeys, newLabels, newHash, newName, members[0].Confidence, removedSlice, actorID, now, basePayload)
		if err != nil {
			return err
		}
		resultIDs = append(resultIDs, added...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resultIDs, nil
}

func (s *SuggestionService) rejectEditedMember(tx *gorm.DB, member DashboardSuggestion, actorID uuid.UUID, now time.Time, basePayload datatypes.JSONMap) error {
	reason := "removed during group edit"
	if err := tx.Model(&DashboardSuggestion{}).
		Where("id = ?", member.ID).
		Updates(map[string]any{
			"status":             DashboardSuggestionStatusRejected,
			"reject_reason":      reason,
			"decided_by_user_id": actorID,
			"decided_at":         now,
		}).Error; err != nil {
		return err
	}
	member.Status = DashboardSuggestionStatusRejected
	member.RejectReason = &reason
	member.DecidedByUserID = &actorID
	member.DecidedAt = &now
	payload := cloneJSONMap(basePayload)
	payload["removed"] = true
	return createSuggestionEvent(tx, &member, DashboardSuggestionEventTypeEdited, &actorID, payload)
}

func (s *SuggestionService) addEditedControls(tx *gorm.DB, sspID, runID uuid.UUID, controlKeys []string, labels map[string]string, labelsHash, name string, confidence float64, removedControlIDs datatypes.JSONSlice[string], actorID uuid.UUID, now time.Time, basePayload datatypes.JSONMap) ([]uuid.UUID, error) {
	if len(controlKeys) == 0 {
		return nil, nil
	}
	labelMap := labelsToJSONMap(labels)
	added := make([]uuid.UUID, 0, len(controlKeys))
	for _, key := range controlKeys {
		catalogID, controlID, err := ParseControlKey(key)
		if err != nil {
			return nil, &EditValidationError{Message: "invalid control key: " + key}
		}
		suggestion := DashboardSuggestion{
			RunID:                  runID,
			SSPID:                  sspID,
			ControlCatalogID:       catalogID,
			ControlID:              controlID,
			LabelSet:               labelMap,
			LabelSetHash:           labelsHash,
			ProposedFilterLabelSet: labelMap,
			ProposedFilterName:     name,
			Reasoning:              "Added by user during group edit",
			Confidence:             confidence,
			Status:                 DashboardSuggestionStatusPending,
			IsUserEdited:           true,
			AddedByUser:            true,
			RemovedControlIds:      removedControlIDs,
			EditedByUserID:         &actorID,
			EditedAt:               &now,
		}
		create := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&suggestion)
		if create.Error != nil {
			return nil, create.Error
		}
		if create.RowsAffected == 0 {
			// Already represented by a pending suggestion for this control+labels.
			continue
		}
		payload := cloneJSONMap(basePayload)
		payload["added"] = true
		payload["control_key"] = key
		if err := createSuggestionEvent(tx, &suggestion, DashboardSuggestionEventTypeEdited, &actorID, payload); err != nil {
			return nil, err
		}
		added = append(added, *suggestion.ID)
	}
	return added, nil
}

// pendingFilterLabelConflict reports whether a pending suggestion outside the
// edited group already exists for member's control with the target filter hash.
func (s *SuggestionService) pendingFilterLabelConflict(tx *gorm.DB, sspID uuid.UUID, member DashboardSuggestion, newHash string, memberIDs map[uuid.UUID]struct{}) (bool, error) {
	var pending []DashboardSuggestion
	if err := tx.
		Where("ssp_id = ? AND control_catalog_id = ? AND control_id = ? AND status = ?", sspID, member.ControlCatalogID, member.ControlID, DashboardSuggestionStatusPending).
		Find(&pending).Error; err != nil {
		return false, err
	}
	for _, suggestion := range pending {
		if suggestion.ID == nil {
			continue
		}
		if _, isMember := memberIDs[*suggestion.ID]; isMember {
			continue
		}
		if CanonicalLabelSetHash(suggestionFilterLabels(suggestion)) == newHash {
			return true, nil
		}
	}
	return false, nil
}

// computeRemovedControlIDs returns the cumulative set of control IDs removed
// from the group: any previously-removed IDs (mirrored on existing rows) plus
// the rows removed in this edit, minus any control that survives (kept or
// re-added). Comparison folds case to honour the control_id casing invariant,
// while the returned IDs keep their stored casing for display.
func computeRemovedControlIDs(members []DashboardSuggestion, removeSet map[uuid.UUID]struct{}, addControlKeys []string) ([]string, error) {
	surviving := map[string]struct{}{}
	for _, member := range members {
		if _, removed := removeSet[*member.ID]; !removed {
			surviving[strings.ToUpper(member.ControlID)] = struct{}{}
		}
	}
	for _, key := range addControlKeys {
		_, controlID, err := ParseControlKey(key)
		if err != nil {
			return nil, &EditValidationError{Message: "invalid control key: " + key}
		}
		surviving[strings.ToUpper(controlID)] = struct{}{}
	}

	removed := map[string]string{}
	for _, member := range members {
		for _, controlID := range member.RemovedControlIds {
			removed[strings.ToUpper(controlID)] = controlID
		}
		if _, isRemoved := removeSet[*member.ID]; isRemoved {
			removed[strings.ToUpper(member.ControlID)] = member.ControlID
		}
	}

	out := make([]string, 0, len(removed))
	for upper, display := range removed {
		if _, stillPresent := surviving[upper]; !stillPresent {
			out = append(out, display)
		}
	}
	sort.Strings(out)
	return out, nil
}

func normalizeEditedLabels(raw map[string]string) (map[string]string, error) {
	trimmed := make(map[string]string, len(raw))
	for key, value := range raw {
		k := strings.TrimSpace(key)
		if k == "" {
			continue
		}
		trimmed[k] = strings.TrimSpace(value)
	}
	normalized, ok := NormalizeLabelSet(trimmed)
	if !ok {
		return nil, &EditValidationError{Message: "proposed filter labels contain conflicting keys"}
	}
	return normalized, nil
}

func cloneJSONMap(src datatypes.JSONMap) datatypes.JSONMap {
	out := make(datatypes.JSONMap, len(src)+2)
	for key, value := range src {
		out[key] = value
	}
	return out
}
