package suggestions

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	defaultMaxComponents       = 25
	defaultMaxComponentTextLen = 800
	defaultMaxControlTextLen   = 2000
)

func (s *SuggestionService) resolvedControlKeys(sspID uuid.UUID) ([]string, error) {
	var rows []struct {
		CatalogID uuid.UUID `gorm:"column:control_catalog_id"`
		ControlID string    `gorm:"column:control_id"`
	}
	if err := s.db.
		Table("profile_controls").
		Select("DISTINCT profile_controls.control_catalog_id, profile_controls.control_id").
		Joins("JOIN ssp_profiles ON ssp_profiles.profile_id = profile_controls.profile_id").
		Where("ssp_profiles.system_security_plan_id = ?", sspID).
		Order("profile_controls.control_catalog_id ASC, profile_controls.control_id ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, ControlKey(row.CatalogID, row.ControlID))
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *SuggestionService) currentLabelSetHashes() ([]string, error) {
	labelSets, err := s.gatherAllLabelSets()
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(labelSets))
	for _, labelSet := range labelSets {
		hashes = append(hashes, labelSet.Hash)
	}
	sort.Strings(hashes)
	return hashes, nil
}

func (s *SuggestionService) gatherControls(sspID uuid.UUID, controlKeys []string, opts GatherOptions) ([]ControlInput, error) {
	opts = normalizeGatherOptions(opts)
	if len(controlKeys) == 0 {
		return []ControlInput{}, nil
	}
	type controlRow struct {
		CatalogID          uuid.UUID `gorm:"column:catalog_id"`
		ControlID          string    `gorm:"column:control_id"`
		Title              string    `gorm:"column:title"`
		Parts              string    `gorm:"column:parts"`
		CatalogTitle       string    `gorm:"column:catalog_title"`
		ImplementationText string    `gorm:"column:implementation_text"`
	}
	keys := make(map[string]struct{}, len(controlKeys))
	for _, key := range controlKeys {
		keys[key] = struct{}{}
	}
	catalogIDs := make([]uuid.UUID, 0, len(controlKeys))
	controlIDs := make([]string, 0, len(controlKeys))
	for _, key := range controlKeys {
		catalogID, controlID, err := ParseControlKey(key)
		if err != nil {
			return nil, err
		}
		catalogIDs = append(catalogIDs, catalogID)
		controlIDs = append(controlIDs, controlID)
	}

	var rows []controlRow
	if err := s.db.Raw(`
		SELECT
			c.catalog_id,
			c.id AS control_id,
			c.title,
			c.parts::text AS parts,
			COALESCE(m.title, '') AS catalog_title,
			TRIM(CONCAT_WS(E'\n',
				NULLIF(ir.remarks, ''),
				string_agg(NULLIF(st.remarks, ''), E'\n' ORDER BY st.statement_id)
			)) AS implementation_text
		FROM controls c
		JOIN profile_controls pc ON pc.control_catalog_id = c.catalog_id AND pc.control_id = c.id
		JOIN ssp_profiles sp ON sp.profile_id = pc.profile_id AND sp.system_security_plan_id = @ssp_id
		LEFT JOIN metadata m ON m.parent_type = 'catalogs' AND m.parent_id = c.catalog_id::text
		LEFT JOIN control_implementations ci ON ci.system_security_plan_id = @ssp_id
		LEFT JOIN implemented_requirements ir ON ir.control_implementation_id = ci.id AND UPPER(ir.control_id) = UPPER(c.id)
		LEFT JOIN statements st ON st.implemented_requirement_id = ir.id
		WHERE c.catalog_id IN @catalog_ids AND c.id IN @control_ids
		GROUP BY c.catalog_id, c.id, c.title, c.parts, m.title, ir.remarks
		ORDER BY c.catalog_id ASC, c.id ASC
	`, map[string]any{
		"ssp_id":      sspID,
		"catalog_ids": catalogIDs,
		"control_ids": controlIDs,
	}).Scan(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]ControlInput, 0, len(rows))
	seen := map[string]struct{}{}
	for _, row := range rows {
		key := ControlKey(row.CatalogID, row.ControlID)
		if _, wanted := keys[key]; !wanted {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ControlInput{
			ControlKey:         key,
			CatalogID:          row.CatalogID.String(),
			ControlID:          row.ControlID,
			CatalogTitle:       row.CatalogTitle,
			Title:              row.Title,
			Statement:          truncate(extractPartText(row.Parts), opts.MaxControlTextLen),
			ImplementationText: truncate(row.ImplementationText, opts.MaxControlTextLen),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlKey < out[j].ControlKey })
	if len(out) != len(controlKeys) {
		return nil, fmt.Errorf("failed to gather all scoped controls")
	}
	return out, nil
}

func (s *SuggestionService) gatherLabelSets(hashes []string) ([]LabelSetInput, error) {
	all, err := s.gatherAllLabelSets()
	if err != nil {
		return nil, err
	}
	wanted := stringSet(hashes)
	out := make([]LabelSetInput, 0, len(hashes))
	for _, labelSet := range all {
		if _, ok := wanted[labelSet.Hash]; ok {
			out = append(out, labelSet)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out, nil
}

func (s *SuggestionService) gatherAllLabelSets() ([]LabelSetInput, error) {
	type row struct {
		EvidenceID   uuid.UUID `gorm:"column:evidence_id"`
		EvidenceUUID uuid.UUID `gorm:"column:evidence_uuid"`
		Title        string    `gorm:"column:title"`
		LabelName    string    `gorm:"column:labels_name"`
		LabelValue   string    `gorm:"column:labels_value"`
	}
	var rows []row
	if err := s.db.Raw(`
		WITH latest AS (
			SELECT DISTINCT ON (uuid) id, uuid, title, "end"
			FROM evidences
			ORDER BY uuid, "end" DESC
		)
		SELECT latest.id AS evidence_id, latest.uuid AS evidence_uuid, latest.title, el.labels_name, el.labels_value
		FROM latest
		JOIN evidence_labels el ON el.evidence_id = latest.id
		ORDER BY latest.uuid ASC, el.labels_name ASC, el.labels_value ASC
	`).Scan(&rows).Error; err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return []LabelSetInput{}, nil
		}
		return nil, err
	}

	type evidenceGroup struct {
		title  string
		labels map[string]string
	}
	byEvidence := map[uuid.UUID]*evidenceGroup{}
	for _, row := range rows {
		group := byEvidence[row.EvidenceID]
		if group == nil {
			group = &evidenceGroup{title: row.Title, labels: map[string]string{}}
			byEvidence[row.EvidenceID] = group
		}
		group.labels[row.LabelName] = row.LabelValue
	}

	byHash := map[string]*LabelSetInput{}
	for _, group := range byEvidence {
		hash := CanonicalLabelSetHash(group.labels)
		labelSet := byHash[hash]
		if labelSet == nil {
			copied := make(map[string]string, len(group.labels))
			for key, value := range group.labels {
				copied[key] = value
			}
			labelSet = &LabelSetInput{Hash: hash, Labels: copied}
			byHash[hash] = labelSet
		}
		labelSet.EvidenceCount++
		if group.title != "" && len(labelSet.SampleTitles) < 3 {
			labelSet.SampleTitles = append(labelSet.SampleTitles, group.title)
			sort.Strings(labelSet.SampleTitles)
		}
	}

	out := make([]LabelSetInput, 0, len(byHash))
	for _, labelSet := range byHash {
		out = append(out, *labelSet)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out, nil
}

func (s *SuggestionService) gatherSystemContext(sspID uuid.UUID, opts GatherOptions, stats map[string]int) (SystemContextInput, error) {
	opts = normalizeGatherOptions(opts)
	var characteristics relational.SystemCharacteristics
	err := s.db.Where("system_security_plan_id = ?", sspID).First(&characteristics).Error
	if err != nil && !errorsIsRecordNotFound(err) {
		return SystemContextInput{}, err
	}

	type componentRow struct {
		Title       string
		Type        string
		Purpose     string
		Description string
	}
	var rows []componentRow
	if err := s.db.
		Table("system_components").
		Select("title, type, purpose, description").
		Joins("JOIN system_implementations ON system_implementations.id = system_components.system_implementation_id").
		Where("system_implementations.system_security_plan_id = ?", sspID).
		Order("system_components.title ASC, system_components.id ASC").
		Find(&rows).Error; err != nil {
		return SystemContextInput{}, err
	}
	if len(rows) > opts.MaxComponents {
		stats["system_components_overflow"] = len(rows) - opts.MaxComponents
		rows = rows[:opts.MaxComponents]
	}
	components := make([]SystemComponentInput, 0, len(rows))
	for _, row := range rows {
		component := SystemComponentInput{
			Title:       truncate(row.Title, opts.MaxComponentTextLen),
			Type:        truncate(row.Type, opts.MaxComponentTextLen),
			Purpose:     truncate(row.Purpose, opts.MaxComponentTextLen),
			Description: truncate(row.Description, opts.MaxComponentTextLen),
		}
		components = append(components, component)
	}
	return SystemContextInput{
		SystemName:  characteristics.SystemName,
		Description: truncate(characteristics.Description, opts.MaxControlTextLen),
		Components:  components,
	}, nil
}

func (s *SuggestionService) gatherLabelKeyDocs() ([]LabelKeyDocInput, error) {
	type row struct {
		Key         string
		Description *string
	}
	var rows []row
	if err := s.db.Raw(`
		SELECT key, description FROM subject_template_label_schema_fields
		UNION
		SELECT key, description FROM risk_template_label_schema_fields
		ORDER BY key ASC
	`).Scan(&rows).Error; err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return []LabelKeyDocInput{}, nil
		}
		return nil, err
	}
	merged := map[string]string{}
	for _, row := range rows {
		if _, exists := merged[row.Key]; !exists && row.Description != nil {
			merged[row.Key] = *row.Description
		}
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]LabelKeyDocInput, 0, len(keys))
	for _, key := range keys {
		out = append(out, LabelKeyDocInput{Key: key, Description: merged[key]})
	}
	return out, nil
}

func (s *SuggestionService) gatherVisibleFilters(sspID uuid.UUID) ([]VisibleFilterInput, []VisibleFilterInput, []string, error) {
	var filters []relational.Filter
	if err := s.db.
		Where("ssp_id IS NULL OR ssp_id = ?", sspID).
		Order("name ASC, id ASC").
		Find(&filters).Error; err != nil {
		return nil, nil, nil, err
	}
	visible := make([]VisibleFilterInput, 0, len(filters))
	sameSSP := make([]VisibleFilterInput, 0)
	globalNames := make([]string, 0)
	for _, filter := range filters {
		input := VisibleFilterInput{
			ID:    *filter.ID,
			Name:  filter.Name,
			SSPID: filter.SSPID,
		}
		if labels, ok := CanonicalizeFilter(filter.Filter.Data()); ok {
			hash := CanonicalLabelSetHash(labels)
			input.LabelSetHash = &hash
		}
		visible = append(visible, input)
		if filter.SSPID != nil && *filter.SSPID == sspID {
			sameSSP = append(sameSSP, input)
		}
		if filter.SSPID == nil {
			globalNames = append(globalNames, filter.Name)
		}
	}
	sort.Strings(globalNames)
	return visible, sameSSP, globalNames, nil
}

func normalizeGatherOptions(opts GatherOptions) GatherOptions {
	if opts.MaxComponents <= 0 {
		opts.MaxComponents = defaultMaxComponents
	}
	if opts.MaxComponentTextLen <= 0 {
		opts.MaxComponentTextLen = defaultMaxComponentTextLen
	}
	if opts.MaxControlTextLen <= 0 {
		opts.MaxControlTextLen = defaultMaxControlTextLen
	}
	return opts
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + ReasoningTruncatedMarker
}

func extractPartText(partsJSON string) string {
	if strings.TrimSpace(partsJSON) == "" {
		return ""
	}
	var parts []relational.Part
	if err := json.Unmarshal([]byte(partsJSON), &parts); err != nil {
		return ""
	}
	var lines []string
	var walk func([]relational.Part)
	walk = func(items []relational.Part) {
		for _, part := range items {
			if part.Title != "" || part.Prose != "" {
				lines = append(lines, strings.TrimSpace(strings.Join([]string{part.Title, part.Prose}, " ")))
			}
			if len(part.Parts) > 0 {
				walk(part.Parts)
			}
		}
	}
	walk(parts)
	return strings.Join(lines, "\n")
}

func errorsIsRecordNotFound(err error) bool {
	return err == nil || errors.Is(err, gorm.ErrRecordNotFound)
}
