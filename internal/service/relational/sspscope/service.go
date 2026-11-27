package sspscope

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// ErrSSPNotFound is returned when the SSP does not exist.
	ErrSSPNotFound = errors.New("system security plan not found")
	// ErrExceptionNotFound is returned when the exception does not exist on the SSP.
	ErrExceptionNotFound = errors.New("scope exception not found")
	// ErrDuplicateEntry is returned when an entry matching the same evidence exists.
	ErrDuplicateEntry = errors.New("scope entry already exists")
	// ErrDuplicateException is returned when an exception with the same labels exists.
	ErrDuplicateException = errors.New("scope exception already exists")
)

// Scope is an SSP's scope: its entries, exceptions and settings.
type Scope struct {
	AutoFilters bool
	Entries     []relational.SSPScopeEntry
	Exceptions  []relational.SSPScopeException
}

// Service reads and writes SSP scopes. Every write takes a per-SSP advisory lock, so a
// user edit and a template run on the same SSP do not interleave.
type Service struct {
	db *gorm.DB
}

// NewService returns a Service over db.
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// Get returns the SSP's entries (oldest first), exceptions (oldest first) and settings.
func (s *Service) Get(sspID uuid.UUID) (Scope, error) {
	if err := ensureSSP(s.db, sspID); err != nil {
		return Scope{}, err
	}
	scope := Scope{}
	if err := s.db.Where("ssp_id = ?", sspID).Order("created_at ASC, id ASC").Find(&scope.Entries).Error; err != nil {
		return Scope{}, err
	}
	if err := s.db.Where("ssp_id = ?", sspID).Order("created_at ASC, id ASC").Find(&scope.Exceptions).Error; err != nil {
		return Scope{}, err
	}
	// A missing settings row means the defaults.
	var settings []relational.SSPScopeSettings
	if err := s.db.Where("ssp_id = ?", sspID).Limit(1).Find(&settings).Error; err != nil {
		return Scope{}, err
	}
	if len(settings) == 1 {
		scope.AutoFilters = settings[0].AutoFilters
	}
	return scope, nil
}

// AddEntry adds a manual entry. It fails with ErrDuplicateEntry when an entry matching
// the same evidence exists, and deletes an exception with the same labels: adding the
// entry says the user wants it.
func (s *Service) AddEntry(sspID uuid.UUID, labels []relational.ScopeLabel, actor *uuid.UUID) (relational.SSPScopeEntry, error) {
	normalized, hash, err := Normalize(labels)
	if err != nil {
		return relational.SSPScopeEntry{}, err
	}
	entry := relational.SSPScopeEntry{
		SSPID:     sspID,
		Labels:    normalized,
		MatchHash: hash,
		Origin:    relational.ScopeEntryOriginManual,
		CreatedBy: actor,
	}
	err = s.write(sspID, func(tx *gorm.DB) error {
		exists, err := hashExists(tx, &relational.SSPScopeEntry{}, sspID, hash)
		if err != nil {
			return err
		}
		if exists {
			return ErrDuplicateEntry
		}
		if err := checkLimit(tx, &relational.SSPScopeEntry{}, sspID, MaxEntries, "entries"); err != nil {
			return err
		}
		if err := tx.Where("ssp_id = ? AND match_hash = ?", sspID, hash).Delete(&relational.SSPScopeException{}).Error; err != nil {
			return err
		}
		if err := tx.Create(&entry).Error; err != nil {
			return err
		}
		return s.afterChange(tx, sspID)
	})
	return entry, err
}

// AddException adds an exception and deletes the entry with the same labels, if any.
// It fails with ErrDuplicateException when the exception exists, and with
// ErrScopeWouldEmpty (*ScopeWouldEmptyError) when it would remove the last entry while
// filters follow the scope.
func (s *Service) AddException(sspID uuid.UUID, labels []relational.ScopeLabel, actor *uuid.UUID) (relational.SSPScopeException, error) {
	normalized, hash, err := Normalize(labels)
	if err != nil {
		return relational.SSPScopeException{}, err
	}
	exception := relational.SSPScopeException{
		SSPID:     sspID,
		Labels:    normalized,
		MatchHash: hash,
		CreatedBy: actor,
	}
	err = s.write(sspID, func(tx *gorm.DB) error {
		exists, err := hashExists(tx, &relational.SSPScopeException{}, sspID, hash)
		if err != nil {
			return err
		}
		if exists {
			return ErrDuplicateException
		}
		if err := checkLimit(tx, &relational.SSPScopeException{}, sspID, MaxExceptions, "exceptions"); err != nil {
			return err
		}
		if err := checkWouldEmpty(tx, sspID, hash); err != nil {
			return err
		}
		removed := tx.Where("ssp_id = ? AND match_hash = ?", sspID, hash).Delete(&relational.SSPScopeEntry{})
		if removed.Error != nil {
			return removed.Error
		}
		if err := tx.Create(&exception).Error; err != nil {
			return err
		}
		if removed.RowsAffected == 0 {
			return nil
		}
		return s.afterChange(tx, sspID)
	})
	return exception, err
}

// DeleteException deletes only the exception: the entry does not come back. A template
// run re-learns it if evidence still shows it, or the user adds it again.
func (s *Service) DeleteException(sspID, exceptionID uuid.UUID) error {
	return s.write(sspID, func(tx *gorm.DB) error {
		res := tx.Where("id = ? AND ssp_id = ?", exceptionID, sspID).Delete(&relational.SSPScopeException{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrExceptionNotFound
		}
		return nil
	})
}

// SetAutoFilters turns automatic per-policy filters on or off for the SSP. Turning them
// on creates the missing automatic filters in the same transaction.
func (s *Service) SetAutoFilters(sspID uuid.UUID, enabled bool) error {
	return s.write(sspID, func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "ssp_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"auto_filters", "updated_at"}),
		}).Create(&relational.SSPScopeSettings{SSPID: sspID, AutoFilters: enabled}).Error; err != nil {
			return err
		}
		if !enabled {
			return nil
		}
		_, err := reconcileAutoFilters(tx, sspID)
		return err
	})
}

// SkippedEntry is a learned entry that Learn could not store, with the reason.
type SkippedEntry struct {
	Labels []relational.ScopeLabel
	Reason string
}

// LearnResult is what Learn added and what it skipped as invalid.
type LearnResult struct {
	Added   []relational.SSPScopeEntry
	Skipped []SkippedEntry
}

// Learn adds template-origin entries inside the caller's transaction, skipping entries
// that already exist, entries with an exception and repeats within entries. Entries that
// fail Normalize (an evidence value over the length limit, say) are skipped and reported
// in Skipped rather than failing the call. It never removes entries. tx must be an open
// transaction: the SSP's scope lock is transaction-scoped, so outside one it is released
// immediately.
func (s *Service) Learn(tx *gorm.DB, sspID, templateID uuid.UUID, entries [][]relational.ScopeLabel) (LearnResult, error) {
	result := LearnResult{Added: []relational.SSPScopeEntry{}, Skipped: []SkippedEntry{}}
	if err := LockSSP(tx, sspID); err != nil {
		return LearnResult{}, err
	}
	if err := ensureSSP(tx, sspID); err != nil {
		return LearnResult{}, err
	}
	skip := map[string]struct{}{}
	for _, model := range []any{&relational.SSPScopeEntry{}, &relational.SSPScopeException{}} {
		var hashes []string
		if err := tx.Model(model).Where("ssp_id = ?", sspID).Pluck("match_hash", &hashes).Error; err != nil {
			return LearnResult{}, err
		}
		for _, hash := range hashes {
			skip[hash] = struct{}{}
		}
	}
	var count int64
	if err := tx.Model(&relational.SSPScopeEntry{}).Where("ssp_id = ?", sspID).Count(&count).Error; err != nil {
		return LearnResult{}, err
	}

	for _, labels := range entries {
		normalized, hash, err := Normalize(labels)
		if err != nil {
			result.Skipped = append(result.Skipped, SkippedEntry{Labels: labels, Reason: err.Error()})
			continue
		}
		if _, ok := skip[hash]; ok {
			continue
		}
		skip[hash] = struct{}{}
		result.Added = append(result.Added, relational.SSPScopeEntry{
			SSPID:      sspID,
			Labels:     normalized,
			MatchHash:  hash,
			Origin:     relational.ScopeEntryOriginTemplate,
			TemplateID: &templateID,
		})
	}
	if len(result.Added) == 0 {
		return result, nil
	}
	if count+int64(len(result.Added)) > MaxEntries {
		return LearnResult{}, fmt.Errorf("%w: at most %d entries per SSP", ErrLimitExceeded, MaxEntries)
	}
	if err := tx.Create(&result.Added).Error; err != nil {
		return LearnResult{}, err
	}
	if err := s.afterChange(tx, sspID); err != nil {
		return LearnResult{}, err
	}
	return result, nil
}

// Filter returns the SSP's scope as a label filter. ok is false when the scope has no
// entries: an empty scope means the SSP has not declared its evidence, not "everything".
// It returns ErrSSPNotFound when the SSP does not exist.
func (s *Service) Filter(sspID uuid.UUID) (labelfilter.Filter, bool, error) {
	if err := ensureSSP(s.db, sspID); err != nil {
		return labelfilter.Filter{}, false, err
	}
	return scopeFilter(s.db, sspID)
}

func scopeFilter(db *gorm.DB, sspID uuid.UUID) (labelfilter.Filter, bool, error) {
	var entries []relational.SSPScopeEntry
	if err := db.Where("ssp_id = ?", sspID).Find(&entries).Error; err != nil {
		return labelfilter.Filter{}, false, err
	}
	f, ok := ToFilter(entries)
	return f, ok, nil
}

// ToFilter converts entries to a label filter: the OR of the entries, each the AND of
// its labels as "=" conditions. Single-element levels collapse, and entries are ordered
// by MatchHash so the same scope always yields the same filter. ok is false when
// entries is empty.
func ToFilter(entries []relational.SSPScopeEntry) (labelfilter.Filter, bool) {
	if len(entries) == 0 {
		return labelfilter.Filter{}, false
	}
	sorted := append([]relational.SSPScopeEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].MatchHash < sorted[j].MatchHash })

	scopes := make([]labelfilter.Scope, 0, len(sorted))
	for _, entry := range sorted {
		conditions := make([]labelfilter.Scope, 0, len(entry.Labels))
		for _, label := range entry.Labels {
			conditions = append(conditions, labelfilter.Scope{Condition: &labelfilter.Condition{
				Label:    label.Key,
				Operator: "=",
				Value:    label.Value,
			}})
		}
		scopes = append(scopes, collapse("AND", conditions))
	}
	scope := collapse("OR", scopes)
	return labelfilter.Filter{Scope: &scope}, true
}

// And returns base AND scope. A base without a scope, or with an empty one ({"scope":{}},
// the Evidence page's default), matches everything, so the result is scope alone.
func And(base, scope labelfilter.Filter) labelfilter.Filter {
	if isEmpty(base) {
		return scope
	}
	if isEmpty(scope) {
		return base
	}
	return labelfilter.Filter{Scope: &labelfilter.Scope{Query: &labelfilter.Query{
		Operator: "AND",
		Scopes:   []labelfilter.Scope{*base.Scope, *scope.Scope},
	}}}
}

func isEmpty(f labelfilter.Filter) bool {
	return f.Scope == nil || (f.Scope.Condition == nil && f.Scope.Query == nil)
}

func collapse(operator string, scopes []labelfilter.Scope) labelfilter.Scope {
	if len(scopes) == 1 {
		return scopes[0]
	}
	return labelfilter.Scope{Query: &labelfilter.Query{Operator: operator, Scopes: scopes}}
}

// afterChange runs, inside the writing transaction, whatever must follow a change of
// the SSP's entries: filters that follow the scope are rewritten, then, when automatic
// filters are on, the missing ones are created.
func (s *Service) afterChange(tx *gorm.DB, sspID uuid.UUID) error {
	if err := rewriteFollowingFilters(tx, sspID); err != nil {
		return err
	}
	_, err := reconcileAutoFilters(tx, sspID)
	return err
}

// write runs fn in a transaction holding the SSP's scope lock, after checking the SSP
// exists.
func (s *Service) write(sspID uuid.UUID, fn func(tx *gorm.DB) error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := LockSSP(tx, sspID); err != nil {
			return err
		}
		if err := ensureSSP(tx, sspID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// LockSSP takes the SSP's transaction-scoped advisory lock (postgres only).
// tx must be an open transaction; acquire this lock before locking filter rows.
func LockSSP(tx *gorm.DB, sspID uuid.UUID) error {
	if tx.Name() != "postgres" {
		return nil
	}
	sum := sha256.Sum256([]byte("ssp-scope:" + sspID.String()))
	key1 := int32(binary.BigEndian.Uint32(sum[0:4]))
	key2 := int32(binary.BigEndian.Uint32(sum[4:8]))
	return tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", key1, key2).Error
}

func ensureSSP(db *gorm.DB, sspID uuid.UUID) error {
	var count int64
	if err := db.Model(&relational.SystemSecurityPlan{}).Where("id = ?", sspID).Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return ErrSSPNotFound
	}
	return nil
}

func hashExists(tx *gorm.DB, model any, sspID uuid.UUID, hash string) (bool, error) {
	var count int64
	if err := tx.Model(model).Where("ssp_id = ? AND match_hash = ?", sspID, hash).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func checkLimit(tx *gorm.DB, model any, sspID uuid.UUID, limit int, what string) error {
	var count int64
	if err := tx.Model(model).Where("ssp_id = ?", sspID).Count(&count).Error; err != nil {
		return err
	}
	if count >= int64(limit) {
		return fmt.Errorf("%w: at most %d %s per SSP", ErrLimitExceeded, limit, what)
	}
	return nil
}
