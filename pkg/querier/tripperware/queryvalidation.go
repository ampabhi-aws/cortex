package tripperware

import (
	"context"
	"net/http"

	"github.com/prometheus/prometheus/promql/parser"
	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// MaxPromQLASTDepth bounds the depth of the parsed PromQL AST that the query-frontend and
// querier are willing to walk, print or otherwise re-serialise. A single AST level consumes
// several hundred bytes of goroutine stack across parser.ParseExpr, parser.Walk and the
// recursive Node.String implementations, so an untrusted expression nested deeper than this
// would be able to exhaust the goroutine stack (fatal in Go, uncatchable with recover) or
// trigger O(n^2) byte copying inside expr.String().
//
// 1000 is comfortably above anything a legitimate PromQL query would need (hand-written
// queries rarely exceed a handful of nesting levels) while remaining three orders of
// magnitude below the depth required to crash the process.
const MaxPromQLASTDepth = 1000

// ValidateQueryExpressionSize enforces the per-tenant limit on the byte size of a PromQL expression
// before the expression is handed to the parser. Returning a 400 here protects every downstream
// consumer that parses or walks the AST from the unbounded recursion and quadratic re-serialisation
// that can otherwise be triggered by a pathological query parameter.
//
// A limit of 0 (or a request with no tenant) is interpreted as disabled.
func ValidateQueryExpressionSize(ctx context.Context, query string, limits Limits) error {
	if query == "" || limits == nil {
		return nil
	}
	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return nil
	}
	max := validation.SmallestPositiveNonZeroIntPerTenant(tenantIDs, limits.MaxQueryExpressionSizeBytes)
	if max > 0 && len(query) > max {
		return httpgrpc.Errorf(http.StatusBadRequest,
			"query expression size (%d bytes) exceeds the limit of %d bytes", len(query), max)
	}
	return nil
}

// ValidateASTDepth walks the already-parsed PromQL AST iteratively using an explicit worklist
// (so the walk itself does not grow the goroutine stack) and returns an HTTP 400 error if any
// path from the root to a leaf is deeper than maxDepth. A maxDepth <= 0 disables the check.
//
// This is defence-in-depth on top of ValidateQueryExpressionSize: it protects callers that
// must subsequently call expr.String(), parser.Walk or parser.Inspect on an attacker-controlled
// expression, where even a sub-MB input can nest deep enough to crash the process.
func ValidateASTDepth(expr parser.Node, maxDepth int) error {
	if expr == nil || maxDepth <= 0 {
		return nil
	}
	type frame struct {
		node  parser.Node
		depth int
	}
	stack := []frame{{node: expr, depth: 1}}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if top.depth > maxDepth {
			return httpgrpc.Errorf(http.StatusBadRequest,
				"query expression nesting depth exceeds the limit of %d", maxDepth)
		}
		for _, child := range parser.Children(top.node) {
			if child == nil {
				continue
			}
			stack = append(stack, frame{node: child, depth: top.depth + 1})
		}
	}
	return nil
}
