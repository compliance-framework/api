# OSCAL Catalogs: DELETE Endpoints Design

## Summary
- Adds DELETE endpoints for:
  - `DELETE /api/oscal/catalogs/{id}`
  - `DELETE /api/oscal/catalogs/{id}/groups/{group}`
  - `DELETE /api/oscal/catalogs/{id}/controls/{control}`
- Aligns with existing handler conventions (Echo + GORM + Swagger).

## Files Changed
- `internal/api/handler/oscal/catalogs.go`
  - Register DELETE routes
  - Implement `Delete`, `DeleteGroup`, `DeleteControl`
  - Swagger annotations for each delete path
- `internal/api/handler/oscal/catalogs_integration_test.go`
  - `TestCatalogDelete` verifies 204 + subsequent 404

## Behavior
- Authorization: JWT (`OAuth2Password`) as per existing middleware.
- Responses:
  - `204 No Content` on success
  - `404 Not Found` when entity is missing
  - `400 Bad Request` on invalid UUID
  - `500 Internal Server Error` for DB errors
- Consistency:
  - Mirrors delete patterns used in Assessment Plans, Assessment Results, and SSP handlers.

## Dev Approach & Best Practices
- **Router integration**: Added to `Register` alongside existing CRUD handlers.
- **Existence check**: `First(...)` prior to `Delete(...)` to return 404 properly.
- **GORM usage**: `Delete` with scoped conditions (`id`, `catalog_id`) for integrity.
- **Swagger docs**: Summaries, tags, params, responses consistent with repo conventions.
- **Testing**:
  - Integration-style test uses the existing `IntegrationTestSuite` to create, delete, then verify not-found.
  - Local validation performed by building image (`make tag`) and running under local-dev with the image override.

## Local Validation Notes
- Built Docker image: `ghcr.io/compliance-framework/api:latest_local` via `make tag`.
- Ran free stack with image override:
  - `COMPOSE_COMMAND="docker compose" CCF_API_IMAGE=ghcr.io/compliance-framework/api:latest_local make compose-up-free`
- Exercised endpoints with authenticated curl:
  - `DELETE` returned `204`; subsequent `GET` returned `404` (as expected).

