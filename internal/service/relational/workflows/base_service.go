package workflows

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ValidationError marks a user-visible input validation failure.
// Handlers map this to HTTP 400; anything else is treated as a system error (500).
type ValidationError struct {
	msg string
}

func (e *ValidationError) Error() string { return e.msg }

func validationError(msg string) error {
	return &ValidationError{msg: msg}
}

func validationErrorf(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// BaseService provides common CRUD operations for workflow entities
type BaseService struct {
	db *gorm.DB
}

// NewBaseService creates a new BaseService
func NewBaseService(db *gorm.DB) *BaseService {
	return &BaseService{db: db}
}

// HandleRecordNotFoundError wraps GORM record not found errors with entity-specific messages
func (s *BaseService) HandleRecordNotFoundError(err error, id *uuid.UUID, entityName string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("%s with id %s not found", entityName, id.String())
	}

	return err
}

// CheckEntityExists checks if an entity exists by ID and returns appropriate error
func (s *BaseService) CheckEntityExists(entity interface{}, id *uuid.UUID, entityName string) error {
	if err := s.db.First(entity, id).Error; err != nil {
		return s.HandleRecordNotFoundError(err, id, entityName)
	}
	return nil
}

// DeleteEntity performs a soft delete and validates the operation
func (s *BaseService) DeleteEntity(entity interface{}, id *uuid.UUID, entityName string) error {
	result := s.db.Delete(entity, id)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("%s with id %s not found", entityName, id.String())
	}

	return nil
}

// UpdateEntity performs an update with existence check
func (s *BaseService) UpdateEntity(existing interface{}, updates interface{}, id *uuid.UUID, entityName string) error {
	if err := s.CheckEntityExists(existing, id, entityName); err != nil {
		return err
	}

	return s.db.Model(existing).Updates(updates).Error
}

// ValidateUpdatesNotNil checks if updates parameter is nil
func (s *BaseService) ValidateUpdatesNotNil(updates interface{}) error {
	if updates == nil {
		return errors.New("updates cannot be nil")
	}
	// Check if it's a nil pointer (typed nil)
	v := reflect.ValueOf(updates)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return errors.New("updates cannot be nil")
	}
	return nil
}

// ValidateEntityNotNil checks if an entity is nil and returns an appropriate error
func (s *BaseService) ValidateEntityNotNil(entity interface{}, entityName string) error {
	if entity == nil {
		return fmt.Errorf("%s cannot be nil", entityName)
	}
	// Check if it's a nil pointer (typed nil)
	v := reflect.ValueOf(entity)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return fmt.Errorf("%s cannot be nil", entityName)
	}
	return nil
}

// ValidateAndCreate validates an entity is not nil, runs custom validation if provided, then creates it
func (s *BaseService) ValidateAndCreate(entity interface{}, entityName string, customValidate func() error) error {
	if err := s.ValidateEntityNotNil(entity, entityName); err != nil {
		return err
	}

	if customValidate != nil {
		if err := customValidate(); err != nil {
			return err
		}
	}

	return s.db.Create(entity).Error
}

// ValidateAndUpdate validates updates are not nil, runs custom validation if provided, then updates the entity
func (s *BaseService) ValidateAndUpdate(existing interface{}, updates interface{}, id *uuid.UUID, entityName string, customValidate func() error) error {
	if err := s.ValidateUpdatesNotNil(updates); err != nil {
		return err
	}

	if customValidate != nil {
		if err := customValidate(); err != nil {
			return err
		}
	}

	return s.UpdateEntity(existing, updates, id, entityName)
}

// UpdateStatus updates a status field with timestamp management
func (s *BaseService) UpdateStatus(entity interface{}, id *uuid.UUID, status string, statusField string, timestampUpdates map[string]interface{}) error {
	updates := map[string]interface{}{
		statusField: status,
	}

	// Merge timestamp updates
	for key, value := range timestampUpdates {
		updates[key] = value
	}

	return s.db.Model(entity).Where("id = ?", id).Updates(updates).Error
}

// ActivateEntity sets is_active to true
func (s *BaseService) ActivateEntity(entity interface{}, id *uuid.UUID) error {
	return s.db.Model(entity).Where("id = ?", id).Update("is_active", true).Error
}

// DeactivateEntity sets is_active to false
func (s *BaseService) DeactivateEntity(entity interface{}, id *uuid.UUID) error {
	return s.db.Model(entity).Where("id = ?", id).Update("is_active", false).Error
}

// BulkCreate creates multiple entities with validation
func (s *BaseService) BulkCreate(entities interface{}, validateFn func(int) error) error {
	if validateFn != nil {
		if err := validateFn(0); err != nil {
			return err
		}
	}

	return s.db.Create(entities).Error
}

// GetByIDWithPreload retrieves an entity by ID with preloading
func (s *BaseService) GetByIDWithPreload(entity interface{}, id *uuid.UUID, entityName string, preloads ...string) error {
	query := s.db
	for _, preload := range preloads {
		query = query.Preload(preload)
	}

	err := query.First(entity, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%s with id %s not found", entityName, id.String())
		}
		return fmt.Errorf("failed to retrieve %s: %w", entityName, err)
	}

	return nil
}

// GetByIDWithPreloadAndContext retrieves an entity by ID with preloading and context
func (s *BaseService) GetByIDWithPreloadAndContext(ctx context.Context, entity interface{}, id *uuid.UUID, entityName string, preloads ...string) error {
	query := s.db.WithContext(ctx)
	for _, preload := range preloads {
		query = query.Preload(preload)
	}

	err := query.First(entity, id).Error
	if err != nil {
		return s.HandleRecordNotFoundError(err, id, entityName)
	}

	return nil
}

// CountWhere counts records matching a condition
func (s *BaseService) CountWhere(model interface{}, condition string, args ...interface{}) (int64, error) {
	var count int64
	err := s.db.Model(model).Where(condition, args...).Count(&count).Error
	return count, err
}

// ExistsWhere checks if any record exists matching a condition
func (s *BaseService) ExistsWhere(model interface{}, condition string, args ...interface{}) (bool, error) {
	count, err := s.CountWhere(model, condition, args...)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
