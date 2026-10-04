// SPDX-License-Identifier: Apache-2.0

package alertmanager

import (
	"context"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/types"

	util_net "github.com/cortexproject/cortex/pkg/util/net"
)

// firewalledEmailNotifier wraps the upstream Alertmanager email notifier so
// that the per-tenant receivers firewall (-alertmanager.receivers-firewall-*
// flags) is enforced before any TCP/TLS connection is established to the
// tenant-controlled smarthost. The vendored email notifier dials the
// smarthost itself with a bare net.Dialer{} / tls.Dial and does not expose a
// Control / DialContext hook, so Cortex cannot thread the FirewallDialer
// through as it does for every HTTP-based receiver. Without this wrapper a
// tenant that is allowed to upload Alertmanager configurations can bypass the
// documented firewall and reach loopback, link-local, or private endpoints by
// pointing email_configs.smarthost at a blocked address.
type firewalledEmailNotifier struct {
	inner  notify.Notifier
	conf   *config.EmailConfig
	dialer *util_net.FirewallDialer
	logger log.Logger
}

func newFirewalledEmailNotifier(conf *config.EmailConfig, dialer *util_net.FirewallDialer, logger log.Logger, inner notify.Notifier) *firewalledEmailNotifier {
	return &firewalledEmailNotifier{
		inner:  inner,
		conf:   conf,
		dialer: dialer,
		logger: logger,
	}
}

// Notify implements notify.Notifier. It validates the configured smarthost
// against the firewall before delegating to the wrapped notifier.
func (n *firewalledEmailNotifier) Notify(ctx context.Context, alerts ...*types.Alert) (bool, error) {
	if n.dialer != nil && n.conf != nil && n.conf.Smarthost.String() != "" {
		if err := n.dialer.ValidateHostPort(ctx, n.conf.Smarthost.String()); err != nil {
			level.Warn(n.logger).Log(
				"msg", "email notification blocked by receivers firewall",
				"smarthost", n.conf.Smarthost.String(),
				"err", err,
			)
			// Mark as non-retryable: the config itself targets a blocked
			// address, retrying will not help until the tenant changes it.
			return false, errors.Wrap(err, "email smarthost blocked by receivers firewall")
		}
	}
	return n.inner.Notify(ctx, alerts...)
}
