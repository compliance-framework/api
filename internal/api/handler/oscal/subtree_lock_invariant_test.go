package oscal

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const subtreeLockCall = "lockByComponentSubtreeWrite"

// knownLeverageSatisfactionWriters is the set of writers this invariant was written against. It is
// NOT the input to the check — the check DISCOVERS writers by walking the package (see
// discoverLeverageSatisfactionWriters). This map only asserts that the discovery still finds the
// five we know about, so a discovery walk quietly broken by a refactor fails loudly instead of
// passing vacuously.
var knownLeverageSatisfactionWriters = []string{
	// Derives inline (does not go through resyncLeverageSatisfaction), so its lock is
	// load-bearing on its own.
	"ReAttest",
	// Reuses an existing by-component that may already carry other links' inherited/satisfied
	// rows, and resync rewrites the satisfaction of EVERY link on it — so a stale value here
	// corrupts a pre-existing link, not the one being created.
	"Subscribe",
	// The read-modify-write itself. Self-locking, so its callers cannot forget.
	"resyncLeverageSatisfaction",
	// Lock taken early, to cover their own insert/delete as well as the derivation.
	"CreateImplementedRequirementStatementByComponentSatisfied",
	"DeleteImplementedRequirementStatementByComponentSatisfied",
}

// TestEveryLeverageSatisfactionWriterTakesTheSubtreeLock pins the invariant
// lockByComponentSubtreeWrite exists to enforce: every writer that performs a read-modify-write
// over a by-component's subtree — reading its satisfied set and UPDATEing SSPLeverageLink.Satisfaction
// with a value computed in Go — must take the lock, or a concurrent writer's freshly-derived value
// gets overwritten with a stale one.
//
// Writers are DISCOVERED, not listed: the check walks every file in the package for functions that
// reach a satisfaction derivation, and requires each to take the lock. An earlier version iterated a
// hand-maintained allowlist, which could not fail for the regression it existed to catch — a sixth
// writer added without the lock was simply never examined, and "someone forgot" is exactly the
// failure mode here (the invariant has been half-missed twice, each time while the comment claimed
// full coverage).
//
// This is asserted structurally rather than by exercising a race because the lock is a Postgres
// advisory lock and a no-op under the sqlite unit driver, so no *unit* test can observe it. A
// Postgres-backed integration test can — see TestConcurrentSatisfiedWritesConvergeOnProjection in
// the integration suite, which drives the real race this structure stands in for.
func TestEveryLeverageSatisfactionWriterTakesTheSubtreeLock(t *testing.T) {
	files := parsePackageFiles(t)

	writers := discoverLeverageSatisfactionWriters(files)
	require.NotEmpty(t, writers, "discovery found no satisfaction writers at all — the walk is broken, not the code")

	for name, decl := range writers {
		require.Truef(t, callsFunc(decl, subtreeLockCall),
			"%s performs a read-modify-write over a by-component's subtree but never calls %s.\n"+
				"Every such writer must take the lock: it reads the satisfied set and UPDATEs "+
				"SSPLeverageLink.Satisfaction with a value computed in Go, so skipping the lock lets it "+
				"overwrite a concurrent writer's freshly-derived value with a stale one. Partial adoption "+
				"is worse than none — it serializes only the writers that opted in while reading as "+
				"though the subtree were safe.", name, subtreeLockCall)
	}

	// The discovery must still see everything we already knew about.
	for _, known := range knownLeverageSatisfactionWriters {
		require.Containsf(t, writers, known,
			"discovery no longer finds %s. Either it was renamed (update knownLeverageSatisfactionWriters), "+
				"or discoverLeverageSatisfactionWriters has stopped recognising a derivation and this test "+
				"has gone vacuous.", known)
	}
}

// parsePackageFiles parses every non-test .go file in this package.
//
// Files are enumerated and parsed individually rather than via parser.ParseDir, which is deprecated
// as of Go 1.25. The go/packages alternative the deprecation points at would pull a full load
// (and its build-tag handling) into a test that only needs this one directory's syntax trees.
func parsePackageFiles(t *testing.T) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	require.NoError(t, err, "reading package directory")

	files := make([]*ast.File, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoErrorf(t, err, "parsing %s", name)
		// Guard against a stray file declaring another package (e.g. an oscal_test variant).
		if file.Name.Name != "oscal" {
			continue
		}
		files = append(files, file)
	}
	require.NotEmpty(t, files, "package oscal not found in current directory")
	return files
}

// discoverLeverageSatisfactionWriters finds every function that reaches a satisfaction derivation:
// either by calling resyncLeverageSatisfaction, or by deriving inline — writing
// SSPLeverageLink.Satisfaction via an Update/Updates/Save whose target names the satisfaction column.
//
// resyncLeverageSatisfaction itself is included: it IS the read-modify-write, and it self-locks so
// its callers cannot forget. If someone removes that lock as "redundant", this catches it.
func discoverLeverageSatisfactionWriters(files []*ast.File) map[string]*ast.FuncDecl {
	writers := map[string]*ast.FuncDecl{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if callsFunc(fn, "resyncLeverageSatisfaction") || writesLinkSatisfaction(fn) {
				writers[fn.Name.Name] = fn
			}
		}
	}
	return writers
}

// writesLinkSatisfaction reports whether decl contains a GORM write naming the satisfaction column
// — i.e. it derives the value inline rather than delegating to resyncLeverageSatisfaction.
func writesLinkSatisfaction(decl *ast.FuncDecl) bool {
	found := false
	ast.Inspect(decl, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Update", "Updates", "Save":
		default:
			return true
		}
		for _, arg := range call.Args {
			if mentionsSatisfaction(arg) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// mentionsSatisfaction reports whether an expression names the satisfaction column or field,
// covering both Update("satisfaction", v) and Updates(map[string]any{"satisfaction": v}).
func mentionsSatisfaction(expr ast.Node) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING && strings.Contains(strings.ToLower(v.Value), "satisfaction") {
				found = true
				return false
			}
		case *ast.Ident:
			if strings.Contains(strings.ToLower(v.Name), "satisfaction") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// callsFunc reports whether decl's body contains a call to the named function, including inside
// closures (the handlers do their work inside a db.Transaction(func(tx *gorm.DB) error { ... })).
// Both bare calls (foo()) and selector calls (pkg.foo(), h.foo()) count — matching only bare idents
// would go silently blind the moment a call is refactored behind a receiver.
func callsFunc(decl *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(decl, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == name {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if fun.Sel.Name == name {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
