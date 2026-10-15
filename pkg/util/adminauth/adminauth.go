// Package adminauth provides a small shared helper for signalling, through
// the request context, that an HTTP request has been authorised by the
// operator (administrator) authorisation middleware configured in the API
// layer. Handlers that aggregate data across every tenant can use
// Authorized() as a defence-in-depth check so that a route accidentally
// registered without the admin middleware does not silently expose
// cross-tenant data.
package adminauth

import "context"

// contextKey is a private, unexported type to prevent key collisions with
// other packages' context values.
type contextKey struct{}

// With returns a copy of ctx annotated as operator-authorized. Admin
// authorisation middleware MUST attach this value before invoking the next
// handler.
func With(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, true)
}

// Authorized reports whether the context has been marked as
// operator-authorized by an admin-auth middleware.
func Authorized(ctx context.Context) bool {
	v, _ := ctx.Value(contextKey{}).(bool)
	return v
}
