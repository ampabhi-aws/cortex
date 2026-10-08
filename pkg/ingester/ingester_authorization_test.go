// Regression tests for the ingester gRPC authorization surface.
//
// These tests pin two guarantees that proved critical when CWE-1212 /
// CWE-653 was reported against Ingester.AllUserStats:
//
//  1. Every tenant-facing method on client.IngesterServer must either resolve
//     the caller via tenant.TenantID (and therefore cannot be reached by an
//     anonymous or empty-tenant caller) or be explicitly listed below as an
//     operator-only RPC and routed through assertAdminTenant.
//  2. AllUserStats refuses callers that do not assert an admin tenant ID.
package ingester

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/user"
	"google.golang.org/grpc/codes"

	"github.com/gogo/status"
)

// ingesterServerMethods enumerates every exported method on
// client.IngesterServer. The test fails if a method is added to the proto
// without being classified here, so a new RPC cannot silently inherit an
// unscoped data path.
var ingesterServerMethods = []string{
	"Push",
	"Query",
	"QueryStream",
	"QueryExemplars",
	"LabelValues",
	"LabelValuesStream",
	"LabelNames",
	"LabelNamesStream",
	"UserStats",
	"AllUserStats",
	"MetricsForLabelMatchers",
	"MetricsForLabelMatchersStream",
	"MetricsMetadata",
}

// operatorOnlyIngesterMethods lists RPCs that aggregate across tenants and
// therefore cannot resolve a single tenant from the request context. Each
// method in this set MUST gate itself with assertAdminTenant (or an
// equivalent operator check) rather than tenant.TenantID.
var operatorOnlyIngesterMethods = map[string]struct{}{
	"AllUserStats": {},
}

// delegatingIngesterMethods maps stream RPCs that delegate authorization to a
// sibling unary RPC. Each listed stream must call the sibling in its body;
// that sibling is responsible for the tenant.TenantID(ctx) check. Keeping
// this explicit means a future refactor that bypasses the sibling will trip
// the regression test.
var delegatingIngesterMethods = map[string]string{
	"LabelValuesStream":             "LabelValues",
	"LabelNamesStream":              "LabelNames",
	"MetricsForLabelMatchersStream": "MetricsForLabelMatchers",
}

// Test_IngesterServer_AllMethodsAreTenantScoped parses pkg/ingester/ingester.go
// and asserts that every client.IngesterServer method either calls
// tenant.TenantID(ctx) in its body (per-tenant scoping, the house pattern) or
// is explicitly listed in operatorOnlyIngesterMethods AND calls
// assertAdminTenant(ctx). This is the regression required by mitigation #3 of
// the AllUserStats finding.
func Test_IngesterServer_AllMethodsAreTenantScoped(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "unable to resolve test file location")
	srcPath := filepath.Join(filepath.Dir(thisFile), "ingester.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, parser.ParseComments)
	require.NoError(t, err, "unable to parse %s", srcPath)

	// Build a method name -> body source lookup for methods with an *Ingester
	// receiver.
	bodies := make(map[string]string)
	for _, decl := range file.Decls {
		fn, isFn := decl.(*ast.FuncDecl)
		if !isFn || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		recvType := ""
		switch t := fn.Recv.List[0].Type.(type) {
		case *ast.StarExpr:
			if ident, ok := t.X.(*ast.Ident); ok {
				recvType = ident.Name
			}
		case *ast.Ident:
			recvType = t.Name
		}
		if recvType != "Ingester" {
			continue
		}
		if fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		src, readErr := readSliceFromFile(srcPath, start, end)
		require.NoError(t, readErr)
		bodies[fn.Name.Name] = src
	}

	for _, method := range ingesterServerMethods {
		body, found := bodies[method]
		require.Truef(t, found, "ingester.go does not declare *Ingester.%s", method)

		_, operatorOnly := operatorOnlyIngesterMethods[method]
		delegatesTo, delegates := delegatingIngesterMethods[method]
		callsTenantID := strings.Contains(body, "tenant.TenantID(")
		callsAssertAdmin := strings.Contains(body, "assertAdminTenant(")

		switch {
		case operatorOnly:
			assert.Truef(t, callsAssertAdmin,
				"operator-only RPC *Ingester.%s must gate itself via assertAdminTenant(ctx)", method)
		case delegates:
			callsSibling := strings.Contains(body, "i."+delegatesTo+"(")
			sibling, siblingFound := bodies[delegatesTo]
			require.Truef(t, siblingFound, "delegate target *Ingester.%s is missing", delegatesTo)
			siblingScoped := strings.Contains(sibling, "tenant.TenantID(") || strings.Contains(sibling, "assertAdminTenant(")
			assert.Truef(t, callsSibling && siblingScoped,
				"delegating RPC *Ingester.%s must call i.%s() (which must itself scope the tenant)", method, delegatesTo)
		default:
			assert.Truef(t, callsTenantID,
				"RPC *Ingester.%s must resolve the caller via tenant.TenantID(ctx) or be added to operatorOnlyIngesterMethods", method)
		}
	}
}

// Test_AllUserStats_RequiresAdminTenant pins the runtime behaviour: callers
// that do not assert an admin tenant ID are rejected with PermissionDenied
// by the operator-only authorization gate.
func Test_AllUserStats_RequiresAdminTenant(t *testing.T) {
	cfg := defaultIngesterTestConfig(t)
	i := &Ingester{cfg: cfg}

	// No tenant in context -> PermissionDenied.
	err := i.assertAdminTenant(context.Background())
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error, got %T: %v", err, err)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	// Wrong tenant -> PermissionDenied.
	ctx := user.InjectOrgID(context.Background(), "attacker")
	err = i.assertAdminTenant(ctx)
	require.Error(t, err)
	st, ok = status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	// Default admin tenant ("1") passes the authorization gate.
	ctx = user.InjectOrgID(context.Background(), "1")
	require.NoError(t, i.assertAdminTenant(ctx))
}

// Test_AssertAdminTenant_AllowList exercises the configurable allow-list.
func Test_AssertAdminTenant_AllowList(t *testing.T) {
	cfg := defaultIngesterTestConfig(t)
	cfg.AdminTenantIDs = "ops-a, ops-b"
	i := &Ingester{cfg: cfg}

	for _, tenantID := range []string{"ops-a", "ops-b"} {
		ctx := user.InjectOrgID(context.Background(), tenantID)
		require.NoError(t, i.assertAdminTenant(ctx), "tenant %q should be allowed", tenantID)
	}

	for _, tenantID := range []string{"1", "fake", "attacker"} {
		ctx := user.InjectOrgID(context.Background(), tenantID)
		err := i.assertAdminTenant(ctx)
		require.Error(t, err, "tenant %q should be rejected", tenantID)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	}

	// Empty allow-list disables the check (opt-out, documented in the flag
	// help text). Callers still need to assert some tenant ID so that
	// anonymous callers remain rejected.
	cfg.AdminTenantIDs = ""
	i = &Ingester{cfg: cfg}
	require.NoError(t, i.assertAdminTenant(user.InjectOrgID(context.Background(), "anybody")))
	require.Error(t, i.assertAdminTenant(context.Background()))
}

// readSliceFromFile returns the file's bytes[start:end] as a string. It is a
// tiny helper so the ast walk above can look at raw source rather than
// re-walking the AST for every call expression we care about.
func readSliceFromFile(path string, start, end int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if start < 0 {
		start = 0
	}
	if end > len(data) {
		end = len(data)
	}
	return string(data[start:end]), nil
}
