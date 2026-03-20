# Plan: Filter-Based Risk SSP Resolution

## Context

Currently, risks are only created after a user manually creates System Components (via apply-suggestion). The chain is:
`Evidence → Components → SystemImplementation → SSP → Risk`

This requires user action and only triggers on "not-satisfied" evidence. We want:
1. **Decouple from system components** — resolve SSPs via `Evidence labels → Filters → Controls → SSPs`
2. **Trigger on ALL evidence** — not just failures — to prepare for future risk resolution logic (open → remediated)
3. **Completely replace** the component-based SSP resolution (no fallback)

## Approach: In-Worker Filter Evaluation

Modify the existing risk worker to resolve SSPs via Filters instead of Components. No new tables, workers, or River flows.

**Why not a cache table?** At expected scale (hundreds of filters), in-memory evaluation is negligible. Cache adds invalidation complexity for no measurable gain. Can be added later if needed.

## Implementation Steps

### Step 1: Add Go-based label filter matcher

**New file:** `internal/converters/labelfilter/matcher.go`

```go
func MatchLabels(scope *Scope, labels map[string][]string) bool
func NormalizeLabels(labels []struct{ Name, Value string }) map[string][]string
```

- Evaluates filter `Scope` (nested AND/OR `Condition`s) against a normalized label map
- Case-insensitive matching (consistent with SQL evaluator in `evidence.go`)
- Nil scope → true (empty filter matches everything)

**New file:** `internal/converters/labelfilter/matcher_test.go`

### Step 2: Rename job to handle all evidence (not just failures)

**Modify:** `internal/service/worker/jobs.go`
- Rename `JobTypeRiskProcessEvidenceFailure` → `JobTypeRiskProcessEvidence` (`"risk_process_evidence"`)
- Rename `RiskProcessEvidenceFailureArgs` → `RiskProcessEvidenceArgs`
- Rename `JobInsertOptionsForRiskProcessEvidenceFailure` → `JobInsertOptionsForRiskProcessEvidence`

**Modify:** `internal/service/worker/service.go`
- Rename `EnqueueRiskProcessEvidenceFailure` → `EnqueueRiskProcessEvidence`

**Modify:** `internal/service/relational/evidence/service.go`
- Rename `RiskJobEnqueuer` interface method
- **Remove** the `statusData.State == EvidenceStatusNotSatisfied` guard — always enqueue
- Always set `shouldEnqueueRiskJob = true` after evidence creation

**Modify:** All test files referencing the old names

### Step 3: Add filter-based SSP resolution to risk worker

**Modify:** `internal/service/worker/risk_evidence_worker.go`

Add new method:
```go
func (w *RiskEvidenceWorker) resolveSSPsViaFilters(ctx context.Context, evidenceLabels []relational.Labels) ([]resolvedSSPInfo, error)
```

Implementation:
1. `db.Find(&filters)` — load all filters
2. Normalize evidence labels into `map[string][]string`
3. Evaluate each filter via `labelfilter.MatchLabels`
4. Single SQL query for matching filter IDs → SSPs + control info:

```sql
SELECT DISTINCT ci.system_security_plan_id, fc.control_catalog_id, fc.control_id
FROM filter_controls fc
JOIN implemented_requirements ir ON UPPER(ir.control_id) = UPPER(fc.control_id)
JOIN control_implementations ci ON ci.id = ir.control_implementation_id
WHERE fc.filter_id IN (?)
```

Return type groups control links by SSP ID:
```go
type resolvedSSPInfo struct {
    SSPID        uuid.UUID
    ControlLinks []controlLinkInfo  // {CatalogID, ControlID} pairs
}
type controlLinkInfo struct {
    CatalogID uuid.UUID
    ControlID string
}
```

### Step 4: Refactor `Work()` and `createOrUpdateRisksForSSPs`

**Modify:** `internal/service/worker/risk_evidence_worker.go`

- `Work()` calls `resolveSSPsViaFilters` once, passes results to template loop
- For non-"not-satisfied" evidence: early return after filter matching (future: risk resolution)
- `createOrUpdateRisksForSSPs` accepts `[]resolvedSSPInfo` instead of extracting from components
- **Remove** `extractSSPIDsFromComponents` entirely

```go
func (w *RiskEvidenceWorker) Work(ctx context.Context, job *river.Job[RiskProcessEvidenceArgs]) error {
    evidence := w.loadEvidenceWithRelations(...)

    // Resolve SSPs via filter matching
    sspInfos := w.resolveSSPsViaFilters(ctx, evidence.Labels)
    if len(sspInfos) == 0 { return nil }

    // For now, only create risks for not-satisfied evidence
    // Future: handle risk resolution for satisfied evidence
    if evidence.Status.Data().State != "not-satisfied" { return nil }

    riskTemplates := w.loadRiskTemplates(...)
    filtered := w.filterRiskTemplatesByViolations(...)

    for _, rt := range filtered {
        w.createOrUpdateRisksForSSPs(ctx, rt, evidence, sspInfos)
    }
}
```

### Step 5: Wire control links into `createRiskLinks`

**Modify:** `internal/service/worker/risk_evidence_worker.go`

Update `createRiskLinks` signature to accept `controlLinks []controlLinkInfo`:

```go
func (w *RiskEvidenceWorker) createRiskLinks(ctx, db, riskID, riskSSPID, evidence, controlLinks) error
```

Add control link creation (replaces TODO at current lines 573-574):
```go
for _, cl := range controlLinks {
    link := &risks.RiskControlLink{
        RiskID: riskID, CatalogID: cl.CatalogID, ControlID: cl.ControlID, CreatedAt: now,
    }
    db.Clauses(clause.OnConflict{DoNothing: true}).Create(link)
}
```

Remove the component-link section (lines 510-571) since we're removing component-based resolution. Keep the evidence link creation.

### Step 6: Clean up evidence loading

**Modify:** `internal/service/worker/risk_evidence_worker.go`

In `loadEvidenceWithRelations`, remove the `Preload("Components")` since components are no longer needed for SSP resolution. Keep Labels, Subjects, InventoryItems.

### Step 7: Tests

**Modify:** `internal/service/worker/risk_evidence_worker_test.go`

- Update all references to renamed job types/args
- Add tests for `resolveSSPsViaFilters` (matching/non-matching filters)
- Add test: evidence labels → filter match → SSP found → risk created with control links
- Add test: satisfied evidence → no risks created (early return)
- Remove tests that depend on component-based SSP resolution

**Modify:** `internal/service/relational/evidence/service_test.go` (if exists)
- Update enqueue condition tests (always enqueues now)

## Files Changed

| File | Change |
|------|--------|
| `internal/converters/labelfilter/matcher.go` | **NEW** — `MatchLabels`, `NormalizeLabels` |
| `internal/converters/labelfilter/matcher_test.go` | **NEW** — unit tests |
| `internal/service/worker/risk_evidence_worker.go` | **MODIFY** — replace component-based with filter-based SSP resolution, add control links, update arg types |
| `internal/service/worker/jobs.go` | **MODIFY** — rename job type, args, insert opts |
| `internal/service/worker/service.go` | **MODIFY** — rename enqueue method |
| `internal/service/relational/evidence/service.go` | **MODIFY** — rename interface, always enqueue |
| `internal/service/worker/risk_evidence_worker_test.go` | **MODIFY** — update tests |
| Evidence service tests | **MODIFY** — update enqueue expectations |

## Key References

- Existing filter→control SQL pattern: `system_component_suggestions.go:76-84`
- Label filter types: `converters/labelfilter/labelfilter.go`
- SQL filter evaluation (reference for Go matcher semantics): `relational/evidence.go` — `getScopeClause`/`getConditionClause`
- Risk control link model: `risks/links.go:23-34`
- Worker registration: `jobs.go:660-663`
- Enqueue trigger: `evidence/service.go:134-138` (the guard to remove)

## Verification

1. `go test ./internal/converters/labelfilter/...` — matcher unit tests
2. `go test ./internal/service/worker/...` — worker tests with filter-based resolution
3. `go test ./internal/service/relational/evidence/...` — evidence service enqueue tests
4. Manual test: create Filter linked to Control, create SSP with that Control in an ImplementedRequirement, submit evidence matching filter labels → risk created for SSP with control links, no system components needed
