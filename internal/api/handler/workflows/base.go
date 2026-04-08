package workflows

import (
	"errors"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	// ErrResponseSent is a sentinel error indicating the response was already sent
	ErrResponseSent = errors.New("response already sent")
)

// BaseHandler provides common functionality for workflow handlers
type BaseHandler struct {
	sugar *zap.SugaredLogger
}

type ActorIdentity struct {
	UserID        *uuid.UUID
	Email         string
	Groups        []string
	Identifiers   []string
	SSOExternalID string
}

// HandleError checks if the error is ErrResponseSent and returns nil to Echo
// Otherwise returns the error as-is for Echo to handle
func HandleError(err error) error {
	if errors.Is(err, ErrResponseSent) {
		return nil
	}
	return err
}

// NewBaseHandler creates a new base handler
func NewBaseHandler(sugar *zap.SugaredLogger) *BaseHandler {
	return &BaseHandler{sugar: sugar}
}

// Bind binds a request without validation (used for Update operations with optional fields)
func (b *BaseHandler) Bind(ctx echo.Context, req interface{}) error {
	if err := ctx.Bind(req); err != nil {
		b.sugar.Errorw("Failed to bind request", "error", err)
		err = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		if err != nil {
			return err
		}
		return ErrResponseSent
	}
	return nil
}

// BindAndValidate binds and validates a request
func (b *BaseHandler) BindAndValidate(ctx echo.Context, req interface{}) error {
	if err := ctx.Bind(req); err != nil {
		b.sugar.Errorw("Failed to bind request", "error", err)
		err = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		if err != nil {
			return err
		}
		return ErrResponseSent
	}

	if err := ctx.Validate(req); err != nil {
		b.sugar.Errorw("Failed to validate request", "error", err)
		err = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		if err != nil {
			return err
		}
		return ErrResponseSent
	}

	return nil
}

// ParseUUID parses a UUID from a path parameter
func (b *BaseHandler) ParseUUID(ctx echo.Context, paramName, entityName string) (*uuid.UUID, error) {
	idStr := ctx.Param(paramName)
	id, err := uuid.Parse(idStr)
	if err != nil {
		b.sugar.Errorw("Invalid "+entityName+" ID", "error", err, "param", paramName, "value", idStr)
		err = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		if err != nil {
			return nil, err
		}
		return nil, ErrResponseSent
	}
	return &id, nil
}

// HandleServiceError handles service layer errors with appropriate HTTP status codes
func (b *BaseHandler) HandleServiceError(ctx echo.Context, err error, operation, entityName string) error {
	if err == gorm.ErrRecordNotFound || isNotFoundError(err) {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	b.sugar.Errorw("Failed to "+operation+" "+entityName, "error", err)
	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
}

// RespondOK sends a successful JSON response
func (b *BaseHandler) RespondOK(ctx echo.Context, data interface{}) error {
	return ctx.JSON(http.StatusOK, data)
}

// RespondCreated sends a created JSON response
func (b *BaseHandler) RespondCreated(ctx echo.Context, data interface{}) error {
	return ctx.JSON(http.StatusCreated, data)
}

// RespondNoContent sends a no content response
func (b *BaseHandler) RespondNoContent(ctx echo.Context) error {
	return ctx.NoContent(http.StatusNoContent)
}

// isNotFoundError checks if an error is a "not found" error
func isNotFoundError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

// GetActorFromClaims resolves the authenticated actor from JWT claims.
func (b *BaseHandler) GetActorFromClaims(ctx echo.Context, db *gorm.DB) (*uuid.UUID, string, error) {
	identity, err := b.GetActorIdentityFromClaims(ctx, db)
	if err != nil {
		return nil, "", err
	}
	return identity.UserID, identity.Email, nil
}

// GetActorIdentityFromClaims resolves the authenticated actor and any known group memberships.
func (b *BaseHandler) GetActorIdentityFromClaims(ctx echo.Context, db *gorm.DB) (*ActorIdentity, error) {
	userClaims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || userClaims == nil {
		if err := ctx.JSON(http.StatusUnauthorized, api.NewError(echo.NewHTTPError(http.StatusUnauthorized, "missing authentication claims"))); err != nil {
			return nil, err
		}
		return nil, ErrResponseSent
	}

	email := userClaims.Subject
	var user relational.User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := ctx.JSON(http.StatusNotFound, api.NewError(echo.NewHTTPError(http.StatusNotFound, "user not found"))); err != nil {
				return nil, err
			}
			return nil, ErrResponseSent
		}
		b.sugar.Errorw("Failed to get user by email", "error", err)
		if err := ctx.JSON(http.StatusInternalServerError, api.NewError(err)); err != nil {
			return nil, err
		}
		return nil, ErrResponseSent
	}

	identity := &ActorIdentity{
		UserID: user.ID,
		Email:  email,
		Identifiers: uniqueStringsFold([]string{
			email,
		}),
	}
	if user.ID != nil {
		identity.Identifiers = uniqueStringsFold(append(identity.Identifiers, user.ID.String()))
	}

	var link relational.SSOUserLink
	if err := db.
		Where("user_id = ? AND deleted_at IS NULL", user.ID.String()).
		Order("last_sync DESC").
		First(&link).Error; err == nil {
		identity.Groups = sso.DeserializeStringArray(link.Groups)
		identity.SSOExternalID = link.ExternalID
		identity.Identifiers = uniqueStringsFold(append(identity.Identifiers, link.ExternalID))
	}

	return identity, nil
}

func uniqueStringsFold(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
