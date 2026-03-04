Title: POAM Phase 1 – API Design

Context
- Purpose: Implement Plan of Action and Milestones (POAM) foundation for Risk Register.
- Scope: CRUD for PoamItem and Milestones, optional linkage to Risks, list filters, OpenAPI docs.

Data Model
- poam_items
  - id (uuid, pk), ssp_id (uuid, not null, FK→system_security_plans.id)
  - title (text), description (text)
  - status (text enum: open|in-progress|completed|overdue)
  - deadline (timestamptz, null), resource_required (text, null)
  - poc_name/email/phone (text, null), remarks (text, null)
  - created_at, updated_at
  - indexes: (status), (ssp_id), (deadline)
- poam_item_milestones
  - id (uuid, pk), poam_item_id (uuid, not null, FK→poam_items.id on delete cascade)
  - title (text), description (text)
  - status (text enum: planned|completed)
  - due_date (timestamptz, null), completed_at (timestamptz, null)
  - created_at, updated_at
  - index: (poam_item_id)
- poam_item_risk_links
  - poam_item_id (uuid, not null, FK→poam_items.id on delete cascade)
  - risk_id (uuid, not null, FK→risks.id on delete cascade)
  - unique: (poam_item_id, risk_id)

OSCAL Mapping (Phase 1 alignment)
- PoamItem → oscal.poam-item: uuid/title/description, related-risks via links, CCF props (ccf:deadline, ccf:poc-name, ccf:poc-email, ccf:status).
- Milestone → oscal remediation milestone (title, description, due_date, completed_at).

API Endpoints (/api/poam-items)
- GET /poam-items
  - Filters: status, sspId, riskId (join), deadlineBefore (RFC3339)
  - Returns list of items
- POST /poam-items
  - Transactional create of item, optional milestones, and risk links
- GET /poam-items/{id}
  - Returns item with milestones and risk links
- PUT /poam-items/{id}
  - Updates mutable fields
- DELETE /poam-items/{id}
  - Deletes item and cascades to milestones and links
- GET /poam-items/{id}/milestones
  - Lists milestones for an item
- POST /poam-items/{id}/milestones
  - Adds milestone
- PUT /poam-items/{id}/milestones/{milestoneId}
  - Updates milestone; if status becomes completed, sets completed_at
- DELETE /poam-items/{id}/milestones/{milestoneId}
  - Deletes milestone

Validation & Errors
- UUID parsing for ids
- Status enums enforced at model/DB
- pocEmail basic format validation (client-side preferred; server accepts text)
- 400 for invalid input, 404 for not found, 409 for unique link violation, 500 for DB errors

Auth & Security
- Protected by existing JWT middleware
- Scoped by sspId; align with Risk CRUD authorization

OpenAPI
- swag annotations included in handler
- docs/swagger.(yaml|json) regenerated via `make swag`

Testing
- Unit tests for model constraints and transactional create
- Integration tests for create/list and milestone completed_at behavior (require Docker)
