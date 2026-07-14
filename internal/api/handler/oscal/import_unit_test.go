package oscal

import (
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
)

func implementationStatus(state string) datatypes.JSONType[relational.ImplementationStatus] {
	return datatypes.NewJSONType(relational.ImplementationStatus{
		State: relational.ImplementationStatusState(state),
	})
}

// registeredSSPRoutes returns every route the SSP handler mounts, as "METHOD /path". Route
// existence — and, just as importantly, route *absence* — is part of this feature's contract:
// the whole point of anchoring on the statement is that no requirement-level creation surface
// exists to re-open the hole.
func registeredSSPRoutes(t *testing.T) []string {
	t.Helper()

	pep := middleware.NewPEP(&stubPDP{allow: true}, authz.FailClosed, zap.NewNop().Sugar())
	e := echo.New()
	NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), nil, nil, nil).
		Register(e.Group("/api/oscal/system-security-plans"), pep.For(authz.ResourceSSP))

	routes := make([]string, 0, len(e.Routes()))
	for _, route := range e.Routes() {
		routes = append(routes, route.Method+" "+route.Path)
	}
	return routes
}

// TestValidateSSPByComponentImplementationStatuses: POST /api/oscal/import unmarshalled the
// document and handed it straight to FirstOrCreate, so an invalid implementation-status was
// never rejected and poisoned the tree. It is now validated at both anchoring levels.
func TestValidateSSPByComponentImplementationStatuses(t *testing.T) {
	newSSP := func(requirementStatus, statementStatus string) *relational.SystemSecurityPlan {
		requirement := relational.ImplementedRequirement{ControlId: "ac-2"}

		if requirementStatus != "" {
			requirement.ByComponents = []relational.ByComponent{{
				ComponentUUID:        uuid.New(),
				ImplementationStatus: implementationStatus(requirementStatus),
			}}
		}
		if statementStatus != "" {
			requirement.Statements = []relational.Statement{{
				StatementId: "ac-2_smt.a",
				ByComponents: []relational.ByComponent{{
					ComponentUUID:        uuid.New(),
					ImplementationStatus: implementationStatus(statementStatus),
				}},
			}}
		}

		return &relational.SystemSecurityPlan{
			ControlImplementation: relational.ControlImplementation{
				ImplementedRequirements: []relational.ImplementedRequirement{requirement},
			},
		}
	}

	require.NoError(t, validateSSPByComponentImplementationStatuses(newSSP("implemented", "partial")))

	// An SSP with no implementation-status at all is fine — the field is optional.
	require.NoError(t, validateSSPByComponentImplementationStatuses(newSSP("", "")))

	err := validateSSPByComponentImplementationStatuses(newSSP("totally-made-up", ""))
	require.ErrorContains(t, err, "ac-2")
	require.ErrorContains(t, err, "totally-made-up")

	err = validateSSPByComponentImplementationStatuses(newSSP("", "not-a-state"))
	require.ErrorContains(t, err, "ac-2_smt.a")
	require.ErrorContains(t, err, "not-a-state")
}

// TestValidateSSPByComponentImplementationStatusesAcceptsEveryValidState guards the enum the
// import path now depends on.
func TestValidateSSPByComponentImplementationStatusesAcceptsEveryValidState(t *testing.T) {
	for _, state := range relational.ValidImplementationStatusStates() {
		ssp := &relational.SystemSecurityPlan{
			ControlImplementation: relational.ControlImplementation{
				ImplementedRequirements: []relational.ImplementedRequirement{{
					ControlId: "ac-2",
					ByComponents: []relational.ByComponent{{
						ComponentUUID:        uuid.New(),
						ImplementationStatus: implementationStatus(string(state)),
					}},
				}},
			},
		}
		require.NoErrorf(t, validateSSPByComponentImplementationStatuses(ssp), "state %q must be accepted", state)
	}
}

// TestNoRequirementLevelByComponentPost: the statement is the canonical anchor, so there must be
// no way to create a *new* requirement-anchored by-component. The requirement-level surface is
// read/update/delete only — enough to wind legacy rows down, and nothing more.
func TestNoRequirementLevelByComponentPost(t *testing.T) {
	const (
		requirementByComponents = "/api/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/by-components"
		statementByComponents   = "/api/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components"
	)

	routes := registeredSSPRoutes(t)

	require.NotContains(t, routes, "POST "+requirementByComponents,
		"a requirement-level by-component POST would re-open exactly the hole this work closes")
	require.NotContains(t, routes, "POST "+requirementByComponents+"/:byComponentId")

	// The legacy read/update/delete surface stays, so existing rows remain manageable.
	require.Contains(t, routes, "GET "+requirementByComponents+"/:byComponentId")
	require.Contains(t, routes, "PUT "+requirementByComponents+"/:byComponentId")
	require.Contains(t, routes, "DELETE "+requirementByComponents+"/:byComponentId")

	// Creation happens at the statement level only.
	require.Contains(t, routes, "POST "+statementByComponents)
}

// TestStatementLevelInheritedAndSatisfiedRoutesExist: the consumer-side CRUD exists, and only at
// the statement level.
func TestStatementLevelInheritedAndSatisfiedRoutesExist(t *testing.T) {
	const (
		statementBC   = "/api/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/statements/:stmtId/by-components/:byComponentId"
		requirementBC = "/api/oscal/system-security-plans/:id/control-implementation/implemented-requirements/:reqId/by-components/:byComponentId"
	)

	routes := registeredSSPRoutes(t)

	for _, method := range []string{"GET", "POST"} {
		require.Contains(t, routes, method+" "+statementBC+"/inherited")
		require.Contains(t, routes, method+" "+statementBC+"/satisfied")
	}
	for _, method := range []string{"PUT", "DELETE"} {
		require.Contains(t, routes, method+" "+statementBC+"/inherited/:inheritedId")
		require.Contains(t, routes, method+" "+statementBC+"/satisfied/:satisfiedId")
	}

	// Inherited/Satisfied describe the downstream half of the export -> inherit -> satisfy loop,
	// which is anchored on a statement — there is deliberately no requirement-level surface.
	for _, suffix := range []string{"/inherited", "/satisfied"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			require.NotContains(t, routes, method+" "+requirementBC+suffix)
		}
	}
}

// TestSharedResponsibilityRouteRegistered: the rollup the Controls page reads.
func TestSharedResponsibilityRouteRegistered(t *testing.T) {
	require.Contains(t, registeredSSPRoutes(t),
		"GET /api/oscal/system-security-plans/:id/shared-responsibility")
}
