// Package artifacts stores content-addressed policy evaluation artifacts.
package artifacts

import (
	"context"
	"errors"

	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrNotFound means no artifact has the requested digest.
var ErrNotFound = errors.New("artifact not found")

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// Put stores canonical content of mediaType under its digest and reports whether this call
// created it. Storing content that is already present changes nothing.
func (s *Service) Put(ctx context.Context, mediaType string, canonical []byte, agentID *uuid.UUID) (*artifact.Info, bool, error) {
	row := &relational.Artifact{
		Digest:           artifact.Digest(canonical),
		MediaType:        mediaType,
		SizeBytes:        int64(len(canonical)),
		Content:          canonical,
		CreatedByAgentID: agentID,
	}
	result := s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(row)
	if result.Error != nil {
		return nil, false, result.Error
	}
	if result.RowsAffected == 1 {
		return info(row), true, nil
	}

	existing, err := s.Head(ctx, row.Digest)
	if err != nil {
		return nil, false, err
	}
	return existing, false, nil
}

// Head returns an artifact's metadata without its content.
func (s *Service) Head(ctx context.Context, digest string) (*artifact.Info, error) {
	var row relational.Artifact
	err := s.db.WithContext(ctx).
		Select("digest", "media_type", "size_bytes").
		Where("digest = ?", digest).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return info(&row), nil
}

// Get returns the artifact with digest, content included.
func (s *Service) Get(ctx context.Context, digest string) (*relational.Artifact, error) {
	var row relational.Artifact
	err := s.db.WithContext(ctx).Where("digest = ?", digest).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func info(row *relational.Artifact) *artifact.Info {
	return &artifact.Info{Digest: row.Digest, MediaType: row.MediaType, SizeBytes: row.SizeBytes}
}
