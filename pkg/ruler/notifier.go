package ruler

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	gklog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	config_util "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/dns"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/prometheus/prometheus/notifier"

	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/tls"
)

// tenantLabel is the reserved alert label used to carry the trusted
// (server-authored) tenant identity on the notification path. It mirrors
// the convention used by Cortex's tenant-federation querier.
const tenantLabel = "__tenant_id__"

type NotifierConfig struct {
	TLS       tls.ClientConfig `yaml:",inline"`
	BasicAuth util.BasicAuth   `yaml:",inline"`
}

func (cfg *NotifierConfig) RegisterFlags(f *flag.FlagSet) {
	cfg.TLS.RegisterFlagsWithPrefix("ruler.alertmanager-client", f)
	cfg.BasicAuth.RegisterFlagsWithPrefix("ruler.alertmanager-client.", f)
}

// rulerNotifier bundles a notifier.Manager together with an associated
// Alertmanager service discovery manager and handles the lifecycle
// of both actors.
type rulerNotifier struct {
	notifier  *notifier.Manager
	sdCancel  context.CancelFunc
	sdManager *discovery.Manager
	wg        sync.WaitGroup
	logger    gklog.Logger
}

func newRulerNotifier(o *notifier.Options, l gklog.Logger) *rulerNotifier {
	sdCtx, sdCancel := context.WithCancel(context.Background())
	return &rulerNotifier{
		notifier:  notifier.NewManager(o, l),
		sdCancel:  sdCancel,
		sdManager: discovery.NewManager(sdCtx, l),
		logger:    l,
	}
}

// run starts the notifier. This function doesn't block and returns immediately.
func (rn *rulerNotifier) run() {
	rn.wg.Add(2)
	go func() {
		if err := rn.sdManager.Run(); err != nil {
			level.Error(rn.logger).Log("msg", "error starting notifier discovery manager", "err", err)
		}
		rn.wg.Done()
	}()
	go func() {
		rn.notifier.Run(rn.sdManager.SyncCh())
		rn.wg.Done()
	}()
}

func (rn *rulerNotifier) applyConfig(cfg *config.Config) error {
	if err := rn.notifier.ApplyConfig(cfg); err != nil {
		return err
	}

	sdCfgs := make(map[string]discovery.Configs)
	for k, v := range cfg.AlertingConfig.AlertmanagerConfigs.ToMap() {
		sdCfgs[k] = v.ServiceDiscoveryConfigs
	}
	return rn.sdManager.ApplyConfig(sdCfgs)
}

func (rn *rulerNotifier) stop() {
	rn.sdCancel()
	rn.notifier.Stop()
	rn.wg.Wait()
}

// Builds a Prometheus config.Config from a ruler.Config with just the required
// options to configure notifications to Alertmanager.
//
// If userID is non-empty, an alert relabel rule is added that unconditionally
// stamps the trusted tenant identifier into every outgoing alert as the
// reserved tenantLabel, so Alertmanager receivers can rely on it for
// provenance even when the downstream Alertmanager does not understand the
// X-Scope-OrgID header. For every operator-configured external label, an
// unconditional relabel is also appended, promoting operator labels from
// upstream Prometheus' soft defaults to authoritative values that cannot be
// shadowed by tenant-authored rule labels.
func buildNotifierConfig(rulerConfig *Config, userID string) (*config.Config, error) {
	amURLs := strings.Split(rulerConfig.AlertmanagerURL, ",")
	validURLs := make([]*url.URL, 0, len(amURLs))

	srvDNSregexp := regexp.MustCompile(`^_.+._.+`)
	for _, h := range amURLs {
		url, err := url.Parse(h)
		if err != nil {
			return nil, err
		}

		if url.String() == "" {
			continue
		}

		// Given we only support SRV lookups as part of service discovery, we need to ensure
		// hosts provided follow this specification: _service._proto.name
		// e.g. _http._tcp.alertmanager.com
		if rulerConfig.AlertmanagerDiscovery && !srvDNSregexp.MatchString(url.Host) {
			return nil, fmt.Errorf("when alertmanager-discovery is on, host name must be of the form _portname._tcp.service.fqdn (is %q)", url.Host)
		}

		validURLs = append(validURLs, url)
	}

	relabels := buildAlertRelabelConfigs(rulerConfig.ExternalLabels, userID)

	if len(validURLs) == 0 {
		if len(relabels) == 0 {
			return &config.Config{}, nil
		}
		return &config.Config{
			AlertingConfig: config.AlertingConfig{
				AlertRelabelConfigs: relabels,
			},
		}, nil
	}

	apiVersion := config.AlertmanagerAPIVersionV1
	if rulerConfig.AlertmanangerEnableV2API {
		apiVersion = config.AlertmanagerAPIVersionV2
	}

	amConfigs := make([]*config.AlertmanagerConfig, 0, len(validURLs))
	for _, url := range validURLs {
		amConfigs = append(amConfigs, amConfigFromURL(rulerConfig, url, apiVersion))
	}

	promConfig := &config.Config{
		GlobalConfig: config.GlobalConfig{
			ExternalLabels: rulerConfig.ExternalLabels,
		},
		AlertingConfig: config.AlertingConfig{
			AlertmanagerConfigs: amConfigs,
			AlertRelabelConfigs: relabels,
		},
	}

	return promConfig, nil
}

// buildAlertRelabelConfigs builds the alert relabel rules applied on the
// notification path. The resulting list is applied in order by the vendored
// Prometheus notifier (see Manager.relabelAlerts) and promotes
// operator-owned labels and the trusted tenant identifier above any
// tenant-authored rule labels, which the upstream notifier would otherwise
// treat as winning defaults.
func buildAlertRelabelConfigs(externalLabels []labels.Label, userID string) []*relabel.Config {
	size := len(externalLabels)
	if userID != "" {
		size++
	}
	if size == 0 {
		return nil
	}

	relabels := make([]*relabel.Config, 0, size)
	for _, l := range externalLabels {
		l := l
		relabels = append(relabels, &relabel.Config{
			Action:      relabel.Replace,
			Regex:       relabel.MustNewRegexp("(.*)"),
			TargetLabel: l.Name,
			Replacement: l.Value,
			Separator:   ";",
		})
	}
	if userID != "" {
		relabels = append(relabels, &relabel.Config{
			Action:      relabel.Replace,
			Regex:       relabel.MustNewRegexp("(.*)"),
			TargetLabel: tenantLabel,
			Replacement: userID,
			Separator:   ";",
		})
	}
	return relabels
}

func amConfigFromURL(rulerConfig *Config, url *url.URL, apiVersion config.AlertmanagerAPIVersion) *config.AlertmanagerConfig {
	var sdConfig discovery.Configs
	if rulerConfig.AlertmanagerDiscovery {
		sdConfig = discovery.Configs{
			&dns.SDConfig{
				Names:           []string{url.Host},
				RefreshInterval: model.Duration(rulerConfig.AlertmanagerRefreshInterval),
				Type:            "SRV",
				Port:            0, // Ignored, because of SRV.
			},
		}

	} else {
		sdConfig = discovery.Configs{
			discovery.StaticConfig{
				{
					Targets: []model.LabelSet{{model.AddressLabel: model.LabelValue(url.Host)}},
				},
			},
		}
	}

	amConfig := &config.AlertmanagerConfig{
		APIVersion:              apiVersion,
		Scheme:                  url.Scheme,
		PathPrefix:              url.Path,
		Timeout:                 model.Duration(rulerConfig.NotificationTimeout),
		ServiceDiscoveryConfigs: sdConfig,
		HTTPClientConfig: config_util.HTTPClientConfig{
			TLSConfig: config_util.TLSConfig{
				CAFile:             rulerConfig.Notifier.TLS.CAPath,
				CertFile:           rulerConfig.Notifier.TLS.CertPath,
				KeyFile:            rulerConfig.Notifier.TLS.KeyPath,
				InsecureSkipVerify: rulerConfig.Notifier.TLS.InsecureSkipVerify,
				ServerName:         rulerConfig.Notifier.TLS.ServerName,
			},
		},
	}

	// Check the URL for basic authentication information first
	if url.User != nil {
		amConfig.HTTPClientConfig.BasicAuth = &config_util.BasicAuth{
			Username: url.User.Username(),
		}

		if password, isSet := url.User.Password(); isSet {
			amConfig.HTTPClientConfig.BasicAuth.Password = config_util.Secret(password)
		}
	}

	// Override URL basic authentication configs with hard coded config values if present
	if rulerConfig.Notifier.BasicAuth.IsEnabled() {
		amConfig.HTTPClientConfig.BasicAuth = &config_util.BasicAuth{
			Username: rulerConfig.Notifier.BasicAuth.Username,
			Password: config_util.Secret(rulerConfig.Notifier.BasicAuth.Password),
		}
	}

	return amConfig
}
