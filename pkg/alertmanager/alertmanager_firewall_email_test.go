package alertmanager

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/util/flagext"
	util_net "github.com/cortexproject/cortex/pkg/util/net"
)

// staticFirewallConfigProvider is a minimal FirewallDialerConfigProvider used
// in tests to toggle BlockPrivateAddresses regardless of per-tenant limits.
type staticFirewallConfigProvider struct {
	blockPrivate bool
	blockCIDRs   []flagext.CIDR
}

func (p staticFirewallConfigProvider) BlockCIDRNetworks() []flagext.CIDR { return p.blockCIDRs }
func (p staticFirewallConfigProvider) BlockPrivateAddresses() bool       { return p.blockPrivate }

// TestBuildReceiverIntegrations_EmailFirewallBlocksLoopback is a regression
// test for the SSRF reported as "Alertmanager email receiver bypasses Cortex
// receiver firewall": the vendored email notifier used to dial smtp_smarthost
// with a bare net.Dialer{}/tls.Dial, so BlockPrivateAddresses() was never
// consulted on the SMTP path. The fix wires Cortex's FirewallDialer into
// email.New via a WithDialer option, so every integration constructed in
// buildReceiverIntegrations must now fail to connect to a loopback smarthost
// whenever BlockPrivateAddresses() is true. The firewall-off branch keeps the
// old behaviour (connection is attempted).
func TestBuildReceiverIntegrations_EmailFirewallBlocksLoopback(t *testing.T) {
	// Open a loopback listener so a connection, if the firewall were bypassed,
	// would be accepted rather than refused — this makes the firewall-off and
	// firewall-on cases distinguishable even on CI machines without a free
	// 127.0.0.1 port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	// Accept and immediately close any connections so no SMTP banner is sent;
	// the test only cares whether the dial itself happened.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	requireTLS := false
	receiver := &config.Receiver{
		Name: "e",
		EmailConfigs: []*config.EmailConfig{{
			To:         "victim@internal.example",
			From:       "a@example.com",
			Smarthost:  config.HostPort{Host: host, Port: port},
			Headers:    map[string]string{},
			RequireTLS: &requireTLS,
		}},
	}

	tmpl, err := template.FromGlobs()
	require.NoError(t, err)
	tmpl.ExternalURL = &url.URL{Scheme: "http", Host: "localhost"}
	logger := log.NewNopLogger()
	wrapper := func(_ string, n notify.Notifier) notify.Notifier { return n }

	alert := &types.Alert{Alert: model.Alert{
		Labels:   model.LabelSet{model.AlertNameLabel: "t"},
		StartsAt: time.Now(),
	}}

	for _, firewallEnabled := range []bool{true, false} {
		firewallEnabled := firewallEnabled
		t.Run(map[bool]string{true: "firewall-on", false: "firewall-off"}[firewallEnabled], func(t *testing.T) {
			fw := util_net.NewFirewallDialer(staticFirewallConfigProvider{blockPrivate: firewallEnabled})

			integrations, err := buildReceiverIntegrations(receiver, tmpl, fw, logger, wrapper)
			require.NoError(t, err)
			require.Len(t, integrations, 1)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, notifyErr := integrations[0].Notify(ctx, alert)
			require.Error(t, notifyErr, "email Notify must always error (no real SMTP server), firewall=%v", firewallEnabled)
			if firewallEnabled {
				// Must have been stopped at dial time by FirewallDialer.control.
				assert.Contains(t, notifyErr.Error(), "blocked address",
					"firewall must block SMTP connection to loopback; got %v", notifyErr)
			} else {
				// Dial succeeded (we accepted & closed the TCP connection) so the
				// error must come from a later stage, not the firewall.
				assert.NotContains(t, notifyErr.Error(), "blocked address",
					"firewall is off: dial must not have been blocked; got %v", notifyErr)
			}
		})
	}
}
