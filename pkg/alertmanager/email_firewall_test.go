// Regression test for the email-integration bypass of the receivers firewall.
package alertmanager

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/alertmanager/alertspb"
	"github.com/cortexproject/cortex/pkg/util/flagext"
	util_net "github.com/cortexproject/cortex/pkg/util/net"
)

type firewallTestLimits struct {
	mockAlertManagerLimits
	blockPrivate bool
	blockCIDRs   []flagext.CIDR
}

func (f firewallTestLimits) AlertmanagerReceiversBlockPrivateAddresses(_ string) bool {
	return f.blockPrivate
}
func (f firewallTestLimits) AlertmanagerReceiversBlockCIDRNetworks(_ string) []flagext.CIDR {
	return f.blockCIDRs
}

func listenerThatMustNotBeDialed(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		conn, err := l.Accept()
		if err == nil {
			t.Errorf("firewall bypass: unexpected connection accepted from %s", conn.RemoteAddr())
			_ = conn.Close()
		}
	}()
	return l
}

func Test_EmailIntegration_RespectsReceiversFirewall(t *testing.T) {
	l := listenerThatMustNotBeDialed(t)
	host, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)

	requireTLS := false
	rcv := &config.Receiver{
		Name: "probe",
		EmailConfigs: []*config.EmailConfig{{
			Smarthost:  config.HostPort{Host: host, Port: port},
			To:         "victim@example.com",
			From:       "cortex@example.com",
			Hello:      "cortex",
			Headers:    map[string]string{"Subject": "probe"},
			HTML:       "<html></html>",
			Text:       "probe",
			RequireTLS: &requireTLS,
		}},
	}

	fwLimits := &firewallTestLimits{blockPrivate: true}
	fwDialer := util_net.NewFirewallDialer(newFirewallDialerConfigProvider("tenant-1", fwLimits))

	tmpl, err := template.FromGlobs()
	require.NoError(t, err)

	integrations, err := buildReceiverIntegrations(
		rcv, tmpl, fwDialer, log.NewNopLogger(),
		func(_ string, n notify.Notifier) notify.Notifier { return n },
	)
	require.NoError(t, err)
	require.Len(t, integrations, 1)
	require.Equal(t, "email", integrations[0].Name())

	alert := &types.Alert{Alert: model.Alert{Labels: model.LabelSet{"alertname": "probe"}}}
	_, err = integrations[0].Notify(context.Background(), alert)
	require.Error(t, err, "firewall must refuse the loopback smarthost")
	assert.Truef(t,
		strings.Contains(err.Error(), "blocked address") ||
			strings.Contains(err.Error(), "establish connection to server"),
		"error should come from firewall dialer, got: %v", err)
}

func Test_ValidateUserConfig_RejectsBlockedEmailSmarthost(t *testing.T) {
	cases := map[string]struct {
		smarthost string
		limits    *firewallTestLimits
		wantErr   error
	}{
		"loopback smarthost with firewall enabled is rejected": {
			smarthost: "127.0.0.1:25",
			limits:    &firewallTestLimits{blockPrivate: true},
			wantErr:   errEmailSmarthostNotAllowed,
		},
		"rfc1918 smarthost with firewall enabled is rejected": {
			smarthost: "10.0.0.5:25",
			limits:    &firewallTestLimits{blockPrivate: true},
			wantErr:   errEmailSmarthostNotAllowed,
		},
		"link-local smarthost with firewall enabled is rejected": {
			smarthost: "169.254.169.254:80",
			limits:    &firewallTestLimits{blockPrivate: true},
			wantErr:   errEmailSmarthostNotAllowed,
		},
		"loopback smarthost with firewall disabled is accepted": {
			smarthost: "127.0.0.1:25",
			limits:    &firewallTestLimits{blockPrivate: false},
			wantErr:   nil,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf(`route:
  receiver: probe
receivers:
  - name: probe
    email_configs:
      - to: victim@example.com
        from: cortex@example.com
        smarthost: %s
        hello: cortex
        require_tls: false
        headers:
          Subject: probe
`, tc.smarthost)

			err := validateUserConfig(log.NewNopLogger(),
				alertspb.AlertConfigDesc{User: "tenant-1", RawConfig: raw},
				tc.limits, "tenant-1")
			if tc.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}
