package service

import (
	"fmt"
	"strconv"

	"github.com/labstack/echo/v4"
)

// PaginationConfig holds configuration for pagination behavior
type PaginationConfig struct {
	DefaultLimit int
	MaxLimit     int
}

// NewPaginationConfig creates a new pagination configuration with sensible defaults
func NewPaginationConfig() *PaginationConfig {
	return &PaginationConfig{
		DefaultLimit: 50,
		MaxLimit:     100,
	}
}

// PaginationParams holds parsed pagination parameters
type PaginationParams struct {
	Page   int
	Limit  int
	Offset int
}

// ParseParams extracts and validates pagination parameters from echo context
func (cfg *PaginationConfig) ParseParams(ctx echo.Context) (*PaginationParams, error) {
	page := 1
	limit := cfg.DefaultLimit

	// Parse page parameter
	if pageParam := ctx.QueryParam("page"); pageParam != "" {
		if p, parseErr := strconv.Atoi(pageParam); parseErr == nil {
			if p <= 0 {
				return nil, fmt.Errorf("page must be greater than 0")
			}
			page = p
		} else {
			return nil, fmt.Errorf("invalid page parameter: %s", pageParam)
		}
	}

	// Parse limit parameter
	if limitParam := ctx.QueryParam("limit"); limitParam != "" {
		if l, parseErr := strconv.Atoi(limitParam); parseErr == nil {
			if l <= 0 {
				return nil, fmt.Errorf("limit must be greater than 0")
			}
			// Cap limit at maximum but don't return error - just use max value
			if l > cfg.MaxLimit {
				limit = cfg.MaxLimit
			} else {
				limit = l
			}
		} else {
			return nil, fmt.Errorf("invalid limit parameter: %s", limitParam)
		}
	}

	offset := (page - 1) * limit

	return &PaginationParams{
		Page:   page,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// ListResponse represents a paginated response structure
type ListResponse[T any] struct {
	Data       []T   `json:"data"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int   `json:"totalPages"`
}

// NewListResponse creates a new paginated list response
func NewListResponse[T any](data []T, total int64, page, limit int) *ListResponse[T] {
	totalPages := int((total + int64(limit) - 1) / int64(limit))
	if totalPages < 1 {
		totalPages = 1
	}

	return &ListResponse[T]{
		Data:       data,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
	}
}
