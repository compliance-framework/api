package oscal

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEveryLeverageSatisfactionWriterTakesTheSubtreeLock pins the invariant
// lockByComponentSubtreeWrite exists to enforce: every writer that performs a read-modify-write
// over a by-component's subtree — reading its satisfied set and UPDATEing SSPLeverageLink.Satisfaction
// with a value computed in Go — must take the lock, or a concurrent writer's freshly-derived value
// gets overwritten with a stale one.
//
// This is asserted structurally rather than by exercising a race because the lock is a Postgres
// advisory lock and a no-op under the sqlite unit driver, so no unit test can observe it. The
// invariant has been half-missed twice (the satisfied DELETE, then Subscribe — each time while the
// comment claimed full coverage), and "partial adoption is worse than useless" is precisely the
// failure this guards: three of four writers locking reads as though the subtree were safe.
//
// resyncLeverageSatisfaction takes the lock itself, so the three writers that derive through it are
// covered by construction. It is still asserted here — if someone removes it from resync as
// "redundant", this test names the writers that would silently lose their protection.
func TestEveryLeverageSatisfactionWriterTakesTheSubtreeLock(t *testing.T) {
	const lockCall = "lockByComponentSubtreeWrite"

	// Every function that reaches a satisfaction derivation, and the file it lives in.
	writers := map[string]string{
		// Derives inline (does not go through resyncLeverageSatisfaction), so its lock is
		// load-bearing on its own.
		"ReAttest": "ssp_leverage.go",
		// Reuses an existing by-component that may already carry other links' inherited/satisfied
		// rows, and resync rewrites the satisfaction of EVERY link on it — so a stale value here
		// corrupts a pre-existing link, not the one being created.
		"Subscribe": "ssp_leverage.go",
		// The read-modify-write itself. Self-locking, so its callers cannot forget.
		"resyncLeverageSatisfaction": "ssp_by_components.go",
		// Lock taken early, to cover their own insert/delete as well as the derivation.
		"CreateImplementedRequirementStatementByComponentSatisfied": "ssp_by_components.go",
		"DeleteImplementedRequirementStatementByComponentSatisfied": "ssp_by_components.go",
	}

	fset := token.NewFileSet()
	for fn, file := range writers {
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		require.NoErrorf(t, err, "parsing %s", file)

		decl := findFuncDecl(parsed, fn)
		require.NotNilf(t, decl, "expected to find %s in %s — if it was renamed, update this test rather than deleting the case", fn, file)

		require.Truef(t, callsFunc(decl, lockCall),
			"%s (%s) performs a read-modify-write over a by-component's subtree but never calls %s.\n"+
				"Every such writer must take the lock: it reads the satisfied set and UPDATEs "+
				"SSPLeverageLink.Satisfaction with a value computed in Go, so skipping the lock lets it "+
				"overwrite a concurrent writer's freshly-derived value with a stale one. Partial adoption "+
				"is worse than none — it serializes only the writers that opted in while reading as "+
				"though the subtree were safe.", fn, file, lockCall)
	}
}

func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// callsFunc reports whether decl's body contains a call to the named function, including inside
// closures (the handlers do their work inside a db.Transaction(func(tx *gorm.DB) error { ... })).
func callsFunc(decl *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(decl, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}
