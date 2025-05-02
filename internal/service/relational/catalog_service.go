package relational

import (
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// CatalogService provides CRUD operations for Catalog entities.
type CatalogService struct {
	db     *gorm.DB
	logger *zap.SugaredLogger
}

// NewCatalogService creates a new CatalogService.
func NewCatalogService(db *gorm.DB, logger *zap.SugaredLogger) *CatalogService {
	return &CatalogService{db: db, logger: logger}
}

// GetCatalog retrieves a Catalog by its UUID, preloading associations.
func (s *CatalogService) GetCatalog(id uuid.UUID) (*Catalog, error) {
	var catalog Catalog
	if err := s.db.
		Preload("Metadata").
		First(&catalog, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &catalog, nil
}

// ListCatalogs returns all Catalogs with their associations.
func (s *CatalogService) ListCatalogs() ([]Catalog, error) {
	var catalogs []Catalog
	if err := s.db.
		Preload("Metadata").
		Find(&catalogs).Error; err != nil {
		return nil, err
	}
	return catalogs, nil
}

// CreateCatalog creates a new Catalog record.
func (s *CatalogService) CreateCatalog(catalog *Catalog) error {
	return s.db.Create(catalog).Error
}

// UpdateCatalog saves changes to an existing Catalog.
func (s *CatalogService) UpdateCatalog(catalog *Catalog) error {
	return s.db.Save(catalog).Error
}

// DeleteCatalog removes a Catalog by its UUID.
func (s *CatalogService) DeleteCatalog(id uuid.UUID) error {
	return s.db.Delete(&Catalog{}, "id = ?", id).Error
}
