package sspscope

import (
	"errors"
	"fmt"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

var (
	// ErrScopeEmpty is returned when a filter is asked to follow a scope with no entries.
	ErrScopeEmpty = errors.New("the SSP scope has no entries")
	// ErrScopeWouldEmpty is returned (as *ScopeWouldEmptyError) when a change would
	// leave the scope empty while filters follow it.
	ErrScopeWouldEmpty = errors.New("the change would leave the SSP scope empty while filters follow it")
)

// ScopeWouldEmptyError names how many filters follow the scope that a change would empty.
type ScopeWouldEmptyError struct {
	Following int64
}

func (e *ScopeWouldEmptyError) Error() string {
	return fmt.Sprintf("this would leave the SSP scope empty while %d filter(s) follow it", e.Following)
}

func (e *ScopeWouldEmptyError) Is(target error) bool { return target == ErrScopeWouldEmpty }

// FollowScope returns base AND the SSP's scope: the stored expression of a filter that
// follows the scope. It takes the SSP's scope lock for the rest of tx, so tx must be an
// open transaction and the filter must be written in it; a concurrent scope change then
// waits and rewrites the filter. It fails with ErrSSPNotFound or ErrScopeEmpty.
func FollowScope(tx *gorm.DB, sspID uuid.UUID, base labelfilter.Filter) (labelfilter.Filter, error) {
	if err := LockSSP(tx, sspID); err != nil {
		return labelfilter.Filter{}, err
	}
	if err := ensureSSP(tx, sspID); err != nil {
		return labelfilter.Filter{}, err
	}
	scope, ok, err := scopeFilter(tx, sspID)
	if err != nil {
		return labelfilter.Filter{}, err
	}
	if !ok {
		return labelfilter.Filter{}, ErrScopeEmpty
	}
	return And(base, scope), nil
}

// followingFilters counts the SSP's filters that follow its scope.
func followingFilters(tx *gorm.DB, sspID uuid.UUID) (int64, error) {
	var count int64
	err := tx.Model(&relational.Filter{}).Where("ssp_id = ? AND scope_base IS NOT NULL", sspID).Count(&count).Error
	return count, err
}

// checkWouldEmpty refuses removing the entry with hash when it is the SSP's last entry
// and filters follow the scope.
func checkWouldEmpty(tx *gorm.DB, sspID uuid.UUID, hash string) error {
	var entries []string
	if err := tx.Model(&relational.SSPScopeEntry{}).Where("ssp_id = ?", sspID).Limit(2).Pluck("match_hash", &entries).Error; err != nil {
		return err
	}
	if len(entries) != 1 || entries[0] != hash {
		return nil
	}
	following, err := followingFilters(tx, sspID)
	if err != nil {
		return err
	}
	if following > 0 {
		return &ScopeWouldEmptyError{Following: following}
	}
	return nil
}

// rewriteFollowingFilters sets the stored expression of every filter following the
// SSP's scope to its ScopeBase AND the current scope.
func rewriteFollowingFilters(tx *gorm.DB, sspID uuid.UUID) error {
	var filters []relational.Filter
	if err := tx.Select("id", "scope_base").Where("ssp_id = ? AND scope_base IS NOT NULL", sspID).Find(&filters).Error; err != nil {
		return err
	}
	if len(filters) == 0 {
		return nil
	}
	scope, ok, err := scopeFilter(tx, sspID)
	if err != nil {
		return err
	}
	if !ok {
		return &ScopeWouldEmptyError{Following: int64(len(filters))}
	}
	for _, filter := range filters {
		effective := And(filter.ScopeBase.Data(), scope)
		if err := tx.Model(&relational.Filter{}).Where("id = ?", filter.ID).
			Update("filter", datatypes.NewJSONType(effective)).Error; err != nil {
			return err
		}
	}
	return nil
}
