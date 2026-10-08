package querytee

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/pkg/errors"
)

const orgIDHeader = "X-Scope-OrgId"

// ProxyBackend holds the information of a single backend.
type ProxyBackend struct {
	name     string
	endpoint *url.URL
	client   *http.Client
	timeout  time.Duration

	// forcedOrgID, if non-empty, pins the X-Scope-OrgID header on every forwarded
	// request to this value regardless of what the client sent. Takes precedence
	// over allowedTenants.
	forcedOrgID string

	// allowedTenants, if non-empty, restricts the set of tenants that may be
	// forwarded in the X-Scope-OrgID header. A client-supplied value that is
	// not in this set is rejected.
	allowedTenants map[string]struct{}

	// Whether this is the preferred backend from which picking up
	// the response and sending it back to the client.
	preferred bool
}

// NewProxyBackend makes a new ProxyBackend
func NewProxyBackend(name string, endpoint *url.URL, timeout time.Duration, preferred bool) *ProxyBackend {
	return NewProxyBackendWithTenants(name, endpoint, timeout, preferred, "", nil)
}

// NewProxyBackendWithTenants makes a new ProxyBackend with optional tenant pinning
// and tenant allowlisting controls.
func NewProxyBackendWithTenants(name string, endpoint *url.URL, timeout time.Duration, preferred bool, forcedOrgID string, allowedTenants []string) *ProxyBackend {
	var allowed map[string]struct{}
	if len(allowedTenants) > 0 {
		allowed = make(map[string]struct{}, len(allowedTenants))
		for _, t := range allowedTenants {
			if t == "" {
				continue
			}
			allowed[t] = struct{}{}
		}
	}

	return &ProxyBackend{
		name:           name,
		endpoint:       endpoint,
		timeout:        timeout,
		preferred:      preferred,
		forcedOrgID:    forcedOrgID,
		allowedTenants: allowed,
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("the query-tee proxy does not follow redirects")
			},
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100, // see https://github.com/golang/go/issues/13801
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (b *ProxyBackend) ForwardRequest(orig *http.Request) (int, []byte, error) {
	req, err := b.createBackendRequest(orig)
	if err != nil {
		return 0, nil, err
	}

	return b.doBackendRequest(req)
}

func (b *ProxyBackend) createBackendRequest(orig *http.Request) (*http.Request, error) {
	req, err := http.NewRequest(orig.Method, orig.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Replace the endpoint with the backend one.
	req.URL.Scheme = b.endpoint.Scheme
	req.URL.Host = b.endpoint.Host

	// Prepend the endpoint path to the request path.
	req.URL.Path = path.Join(b.endpoint.Path, req.URL.Path)

	// Replace the auth:
	// - If the endpoint has user and password, use it.
	// - If the endpoint has no user and no password, use the request auth (if any).
	//
	// NOTE: the historical "endpoint user only + client password" merge branch
	// was removed as a security hardening: replaying caller-supplied passwords
	// under a server-chosen username turned query-tee into a password-guessing
	// oracle (CWE-639 / confused deputy) with no legitimate use.
	clientUser, clientPass, clientAuth := orig.BasicAuth()
	endpointUser := b.endpoint.User.Username()
	endpointPass, endpointHasPass := b.endpoint.User.Password()

	if endpointUser != "" && endpointHasPass && endpointPass != "" {
		req.SetBasicAuth(endpointUser, endpointPass)
	} else if endpointUser != "" {
		// Endpoint has a username but no password configured. We refuse to
		// synthesize credentials from the client's password.
		return nil, errors.New("backend endpoint URL has a username but no password; refusing to merge caller-supplied password with a server-chosen username")
	} else if clientAuth {
		req.SetBasicAuth(clientUser, clientPass)
	}

	// Tenant (X-Scope-OrgID) handling. Cortex trusts this header completely,
	// therefore query-tee must either pin it to an operator-configured value
	// or restrict it to an operator-configured allowlist. Blindly forwarding
	// a caller-chosen tenant together with server-side backend credentials is
	// a classic confused-deputy / cross-tenant read vulnerability.
	switch {
	case b.forcedOrgID != "":
		req.Header.Set(orgIDHeader, b.forcedOrgID)
	case len(b.allowedTenants) > 0:
		orgID := orig.Header.Get(orgIDHeader)
		if orgID == "" {
			return nil, errors.New("missing X-Scope-OrgID header")
		}
		if _, ok := b.allowedTenants[orgID]; !ok {
			return nil, fmt.Errorf("tenant %q not allowed", orgID)
		}
		req.Header.Set(orgIDHeader, orgID)
	default:
		// Legacy behaviour (no tenant pinning / allowlisting configured): forward
		// the client-supplied X-Scope-OrgID header verbatim. This path is kept
		// for backwards compatibility; operators are strongly advised to set
		// -backend.tenant-id or -proxy.allowed-tenants whenever the endpoint URL
		// embeds basic-auth credentials AND to deploy query-tee on a network
		// unreachable by untrusted clients.
		if orgID := orig.Header.Get(orgIDHeader); orgID != "" {
			req.Header.Set(orgIDHeader, orgID)
		}
	}

	return req, nil
}

func (b *ProxyBackend) doBackendRequest(req *http.Request) (int, []byte, error) {
	// Honor the read timeout.
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()

	// Execute the request.
	res, err := b.client.Do(req.WithContext(ctx))
	if err != nil {
		return 0, nil, errors.Wrap(err, "executing backend request")
	}

	// Read the entire response body.
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, errors.Wrap(err, "reading backend response")
	}

	return res.StatusCode, body, nil
}
