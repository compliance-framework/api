package evidence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RiskJobEnqueuer interface to avoid circular imports
type RiskJobEnqueuer interface {
	EnqueueRiskProcessEvidence(ctx context.Context, evidenceID uuid.UUID, evidenceEnd, status string) error
}

// ComponentDefinitionResolver resolves or creates ComponentDefinition + DefinedComponent records
// from evidence labels and returns the SystemComponents linked to those DefinedComponents.
type ComponentDefinitionResolver interface {
	ResolveOrUpsertComponentDefinition(input templates.ResolveOrUpsertComponentDefinitionInput) (*templates.ResolveOrUpsertComponentDefinitionResult, error)
	FindSystemComponentsByDefinedComponentIDs(definedComponentIDs []uuid.UUID) ([]relational.SystemComponent, error)
}

type StatusCount struct {
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

type SearchSortBy string

const (
	SearchSortByLastSeenAt SearchSortBy = "lastSeenAt"
	SearchSortByName       SearchSortBy = "name"
	SearchSortByStatus     SearchSortBy = "status"
)

type SearchSortDirection string

const (
	SearchSortDirectionAsc  SearchSortDirection = "asc"
	SearchSortDirectionDesc SearchSortDirection = "desc"
)

type SearchOptions struct {
	Limit         int
	Offset        int
	Name          string
	SortBy        SearchSortBy
	SortDirection SearchSortDirection
}

type EvidenceService struct {
	db           *gorm.DB
	logger       *zap.SugaredLogger
	cfg          *config.Config
	riskEnqueuer RiskJobEnqueuer
	cdResolver   ComponentDefinitionResolver
	signingSvc   *SigningService
}

var unixEpochUTC = time.Unix(0, 0).UTC()

func NewEvidenceService(db *gorm.DB, logger *zap.SugaredLogger, cfg *config.Config, riskEnqueuer RiskJobEnqueuer, opts ...EvidenceServiceOption) *EvidenceService {
	var signingSvc *SigningService
	if cfg != nil && cfg.JWTPrivateKey != nil {
		signingSvc = NewSigningService(cfg.JWTPrivateKey)
	}
	svc := &EvidenceService{db: db, logger: logger, cfg: cfg, riskEnqueuer: riskEnqueuer, signingSvc: signingSvc}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

type EvidenceServiceOption func(*EvidenceService)

func WithComponentDefinitionResolver(resolver ComponentDefinitionResolver) EvidenceServiceOption {
	return func(s *EvidenceService) {
		s.cdResolver = resolver
	}
}

type CreateEvidenceParams struct {
	Evidence       relational.Evidence
	Components     []relational.SystemComponent
	InventoryItems []relational.InventoryItem
	Activities     []relational.Activity
	Subjects       []relational.AssessmentSubject
	Labels         []relational.Labels
	Signer         *SignerContext
}

func (s *EvidenceService) Create(ctx context.Context, params CreateEvidenceParams) (*relational.Evidence, error) {
	var evidence *relational.Evidence
	var shouldEnqueueRiskJob bool
	var riskJobArgs struct {
		evidenceID  uuid.UUID
		evidenceEnd string
		status      string
	}

	// Resolve ComponentDefinitions from labels and merge any linked SystemComponents.
	if s.cdResolver != nil && len(params.Labels) > 0 {
		params.Components = s.resolveAndMergeComponents(params.Labels, params.Components)
	}

	// Use a complete database transaction
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Create all related entities first
		for i := range params.Components {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Components[i]).Error; err != nil {
				return err
			}
		}

		for i := range params.InventoryItems {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.InventoryItems[i]).Error; err != nil {
				return err
			}
		}

		for i := range params.Activities {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Activities[i]).Error; err != nil {
				return err
			}
		}

		for i := range params.Subjects {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Subjects[i]).Error; err != nil {
				return err
			}
		}

		for i := range params.Labels {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Labels[i]).Error; err != nil {
				return err
			}
		}

		if params.Evidence.Expires != nil && params.Evidence.Expires.UTC().Equal(unixEpochUTC) {
			params.Evidence.Expires = nil
		}

		// Set expiry if not provided
		if params.Evidence.Expires == nil && s.cfg != nil {
			baseDate := params.Evidence.End
			if baseDate.IsZero() {
				baseDate = time.Now().UTC()
			}
			expiryDate := baseDate.AddDate(0, s.cfg.EvidenceDefaultExpiryMonths, 0)
			params.Evidence.Expires = &expiryDate
		}

		// Capture evidence status so we can enqueue a risk job after commit.
		statusData := params.Evidence.Status.Data()

		// Create the evidence record — BeforeCreate sets params.Evidence.ID here.
		if err := tx.Create(&params.Evidence).Error; err != nil {
			return err
		}
		evidence = &params.Evidence

		// Always enqueue the risk job for all evidence (not just failures).
		// The worker decides whether to create/resolve risks based on the status.
		shouldEnqueueRiskJob = true
		riskJobArgs.evidenceID = *params.Evidence.ID
		riskJobArgs.evidenceEnd = params.Evidence.End.Format(time.RFC3339)
		riskJobArgs.status = statusData.State

		// Create associations
		if len(params.Activities) > 0 {
			if err := tx.Model(&params.Evidence).Association("Activities").Append(params.Activities); err != nil {
				return err
			}
		}

		if len(params.InventoryItems) > 0 {
			if err := tx.Model(&params.Evidence).Association("InventoryItems").Append(params.InventoryItems); err != nil {
				return err
			}
		}

		if len(params.Components) > 0 {
			if err := tx.Model(&params.Evidence).Association("Components").Append(params.Components); err != nil {
				return err
			}
		}

		if len(params.Subjects) > 0 {
			if err := tx.Model(&params.Evidence).Association("Subjects").Append(params.Subjects); err != nil {
				return err
			}
		}

		if len(params.Labels) > 0 {
			if err := tx.Model(&params.Evidence).Association("Labels").Append(params.Labels); err != nil {
				return err
			}
		}

		if s.signingSvc != nil && params.Signer != nil && !params.Signer.IsEmpty() {
			var persisted relational.Evidence
			if err := s.evidenceQuery(tx).
				First(&persisted, "id = ?", *params.Evidence.ID).Error; err != nil {
				return err
			}

			signature, err := s.signingSvc.SignEvidence(createEvidenceParamsFromModel(&persisted), params.Signer)
			if err != nil {
				return err
			}

			if err := tx.Model(&params.Evidence).
				Update("signature", signature).Error; err != nil {
				return err
			}
			params.Evidence.Signature = signature
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Enqueue the risk job synchronously after the transaction commits.
	// Note: this is not strictly atomic — if the process crashes between commit and enqueue the job
	// is lost. River's UniqueOpts.ByArgs deduplication prevents double-processing if the same
	// evidence is re-submitted. For true atomicity, river.InsertTx with a pgx.Tx would be required,
	// but that is not directly accessible from within a GORM transaction.
	if shouldEnqueueRiskJob && s.riskEnqueuer != nil {
		if err := s.riskEnqueuer.EnqueueRiskProcessEvidence(ctx,
			riskJobArgs.evidenceID, riskJobArgs.evidenceEnd, riskJobArgs.status); err != nil {
			if s.logger != nil {
				s.logger.Errorw("Failed to enqueue risk process evidence job",
					"error", err, "evidence_id", riskJobArgs.evidenceID)
			}
		}
	}

	return evidence, nil
}

func (s *EvidenceService) GetByID(id uuid.UUID) (*relational.Evidence, error) {
	var evidence relational.Evidence
	if err := s.evidenceQuery(s.db).
		First(&evidence, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &evidence, nil
}

func (s *EvidenceService) GetHistory(streamUUID uuid.UUID) ([]relational.Evidence, error) {
	var evidences []relational.Evidence
	if err := s.evidenceQuery(s.db).
		Order("evidences.end DESC").
		Find(&evidences, "uuid = ?", streamUUID).Error; err != nil {
		return nil, err
	}
	return evidences, nil
}

func (s *EvidenceService) GetHistoryPaginated(streamUUID uuid.UUID, limit, offset int) ([]relational.Evidence, int64, error) {
	query := s.evidenceQuery(s.db).Where("uuid = ?", streamUUID)

	var total int64
	if err := query.Model(&relational.Evidence{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var evidences []relational.Evidence
	if err := query.
		Order("evidences.end DESC").
		Limit(limit).
		Offset(offset).
		Find(&evidences).Error; err != nil {
		return nil, 0, err
	}

	return evidences, total, nil
}

func (s *EvidenceService) GetLatestByUUID(streamUUID uuid.UUID) (*relational.Evidence, error) {
	var evidence relational.Evidence
	if err := s.evidenceQuery(s.db).
		Order("evidences.end DESC").
		First(&evidence, "uuid = ?", streamUUID).Error; err != nil {
		return nil, err
	}
	return &evidence, nil
}

func (s *EvidenceService) evidenceQuery(db *gorm.DB) *gorm.DB {
	return db.
		Preload("Labels").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Preload("Activities").
		Preload("Activities.Steps").
		Preload("InventoryItems").
		Preload("InventoryItems.ImplementedComponents").
		Preload("Components").
		Preload("Subjects").
		Preload("Subjects.IncludeSubjects").
		Preload("Subjects.ExcludeSubjects")
}

func (s *EvidenceService) Search(filter labelfilter.Filter) ([]relational.Evidence, error) {
	var results []relational.Evidence
	query, err := relational.GetEvidenceSearchByFilterQuery(relational.GetLatestEvidenceStreamsQuery(s.db), s.db, filter)
	if err != nil {
		return nil, err
	}
	if err := query.Preload("Labels").Find(&results).Error; err != nil {
		return nil, err
	}
	return results, nil
}

func (s *EvidenceService) SearchPaginated(filter labelfilter.Filter, opts SearchOptions) ([]relational.Evidence, int64, error) {
	opts = normalizeEvidenceSearchOptions(opts)

	query, err := relational.GetEvidenceSearchByFilterQuery(relational.GetLatestEvidenceStreamsQuery(s.db), s.db, filter)
	if err != nil {
		return nil, 0, err
	}

	if name := strings.TrimSpace(opts.Name); name != "" {
		query = query.Where("l.title ILIKE ? ESCAPE '\\'", "%"+escapeILikePattern(name)+"%")
	}

	var total int64
	if err := query.Model(&relational.Evidence{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var results []relational.Evidence
	if err := query.
		Preload("Labels").
		Scopes(applyEvidenceSearchOrder(opts.SortBy, opts.SortDirection)).
		Limit(opts.Limit).
		Offset(opts.Offset).
		Find(&results).Error; err != nil {
		return nil, 0, err
	}

	return results, total, nil
}

func escapeILikePattern(value string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	)
	return replacer.Replace(value)
}

func normalizeEvidenceSearchOptions(opts SearchOptions) SearchOptions {
	if opts.SortBy == "" {
		opts.SortBy = SearchSortByLastSeenAt
	}
	if opts.SortDirection == "" {
		opts.SortDirection = SearchSortDirectionDesc
	}
	return opts
}

func applyEvidenceSearchOrder(sortBy SearchSortBy, direction SearchSortDirection) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		desc := direction == SearchSortDirectionDesc

		switch sortBy {
		case SearchSortByName:
			db = db.Order(clause.OrderByColumn{
				Column: clause.Column{Table: "l", Name: "title"},
				Desc:   desc,
			})
		case SearchSortByStatus:
			sqlDirection := "ASC"
			if desc {
				sqlDirection = "DESC"
			}
			db = db.Order(fmt.Sprintf("l.status->>'state' %s", sqlDirection))
		case SearchSortByLastSeenAt:
			fallthrough
		default:
			db = db.Order(clause.OrderByColumn{
				Column: clause.Column{Table: "l", Name: "end"},
				Desc:   desc,
			})
		}

		return db.
			Order(clause.OrderByColumn{Column: clause.Column{Table: "l", Name: "uuid"}}).
			Order(clause.OrderByColumn{Column: clause.Column{Table: "l", Name: "id"}})
	}
}

func (s *EvidenceService) GetLatestForFilters(filters ...labelfilter.Filter) ([]relational.Evidence, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, filters...)
	if err != nil {
		return nil, err
	}
	var evidences []relational.Evidence
	if err := q.Model(&relational.Evidence{}).Scan(&evidences).Error; err != nil {
		return nil, err
	}
	return evidences, nil
}

func (s *EvidenceService) GetStatusCountsAtPoint(filter labelfilter.Filter, endBefore *time.Time) ([]StatusCount, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	if endBefore != nil {
		latestQuery = latestQuery.Where("evidences.end < ?", endBefore.UTC())
	}
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, filter)
	if err != nil {
		return nil, err
	}
	var rows []StatusCount
	if err := q.Model(&relational.Evidence{}).
		Select("count(DISTINCT uuid) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return nonNilStatusCounts(rows), nil
}

func (s *EvidenceService) GetStatusCountsByUUIDAtPoint(streamUUID uuid.UUID, endBefore *time.Time) ([]StatusCount, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	latestQuery = latestQuery.Where("uuid = ?", streamUUID.String())
	if endBefore != nil {
		latestQuery = latestQuery.Where("evidences.end < ?", endBefore.UTC())
	}
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, labelfilter.Filter{})
	if err != nil {
		return nil, err
	}
	var rows []StatusCount
	if err := q.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return nonNilStatusCounts(rows), nil
}

func (s *EvidenceService) GetStatusCountsByFilters(filters ...labelfilter.Filter) ([]StatusCount, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, filters...)
	if err != nil {
		return nil, err
	}
	var rows []StatusCount
	if err := q.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return nonNilStatusCounts(rows), nil
}

func nonNilStatusCounts(rows []StatusCount) []StatusCount {
	if rows == nil {
		return []StatusCount{}
	}
	return rows
}

func (s *EvidenceService) GetFilterByID(id uuid.UUID) (*relational.Filter, error) {
	var filter relational.Filter
	if err := s.db.First(&filter, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &filter, nil
}

func (s *EvidenceService) GetControlByID(id string) (*relational.Control, error) {
	var control relational.Control
	if err := s.db.Preload("Filters").First(&control, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &control, nil
}

// resolveAndMergeComponents uses the ComponentDefinition resolver to discover
// SystemComponents from evidence labels and merges them into the existing list,
// deduplicating by ID.
func (s *EvidenceService) resolveAndMergeComponents(labels []relational.Labels, existing []relational.SystemComponent) []relational.SystemComponent {
	definedComponentIDs := s.resolveDefinedComponentIDs(labels)
	if len(definedComponentIDs) == 0 {
		return existing
	}

	discovered, err := s.cdResolver.FindSystemComponentsByDefinedComponentIDs(definedComponentIDs)
	if err != nil {
		if s.logger != nil {
			s.logger.Warnw("Failed to find system components by defined component IDs", "error", err)
		}
		return existing
	}

	return mergeSystemComponents(existing, discovered)
}

func (s *EvidenceService) resolveDefinedComponentIDs(labels []relational.Labels) []uuid.UUID {
	result, err := s.cdResolver.ResolveOrUpsertComponentDefinition(templates.ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: labels,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.Warnw("Failed to resolve component definitions from evidence labels", "error", err)
		}
		return nil
	}
	if result == nil {
		return nil
	}
	return result.DefinedComponentIDs
}

func mergeSystemComponents(existing, discovered []relational.SystemComponent) []relational.SystemComponent {
	seen := make(map[uuid.UUID]struct{}, len(existing))
	for _, c := range existing {
		if c.ID != nil {
			seen[*c.ID] = struct{}{}
		}
	}

	for _, sc := range discovered {
		if sc.ID == nil {
			continue
		}
		if _, exists := seen[*sc.ID]; exists {
			continue
		}
		seen[*sc.ID] = struct{}{}
		existing = append(existing, sc)
	}

	return existing
}
