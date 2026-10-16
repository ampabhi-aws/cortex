package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/version"
	"github.com/weaveworks/common/instrument"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/util/flagext"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
	tls_cfg "github.com/cortexproject/cortex/pkg/util/tls"
)

var (
	errBadURL = errors.New("configs_api_url is not set or valid")
)

// Config says where we can find the ruler userconfig.
type Config struct {
	ConfigsAPIURL flagext.URLValue     `yaml:"configs_api_url"`
	ClientTimeout time.Duration        `yaml:"client_timeout"` // HTTP timeout duration for requests made to the Weave Cloud configs service.
	TLS           tls_cfg.ClientConfig `yaml:",inline"`
	// TenantID is the X-Scope-OrgID value injected into requests to the
	// configs service. The configs service /private/api/prom/configs/*
	// endpoints are authenticated and return every tenant's configuration,
	// so this must be set to an operator-scoped tenant ID that is
	// recognised by the configs service's auth layer.
	TenantID string `yaml:"tenant_id"`
}

// RegisterFlagsWithPrefix adds the flags required to config this to the given FlagSet
func (cfg *Config) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.Var(&cfg.ConfigsAPIURL, prefix+"configs.url", "URL of configs API server.")
	f.DurationVar(&cfg.ClientTimeout, prefix+"configs.client-timeout", 5*time.Second, "Timeout for requests to Weave Cloud configs service.")
	f.StringVar(&cfg.TenantID, prefix+"configs.tenant-id", "cortex", "Operator tenant ID sent as X-Scope-OrgID when polling the configs service /private/ endpoints. The configs service rejects unauthenticated requests to these endpoints because they return every tenant's rules and alertmanager_config.")
	cfg.TLS.RegisterFlagsWithPrefix(prefix+"configs", f)
}

var configsRequestDuration = instrument.NewHistogramCollector(promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "cortex",
	Name:      "configs_request_duration_seconds",
	Help:      "Time spent requesting userconfig.",
	Buckets:   prometheus.DefBuckets,
}, []string{"operation", "status_code"}))

// Client is what the ruler and altermanger needs from a config store to process rules.
type Client interface {
	// GetRules returns all Cortex configurations from a configs API server
	// that have been updated after the given userconfig.ID was last updated.
	GetRules(ctx context.Context, since userconfig.ID) (map[string]userconfig.VersionedRulesConfig, error)

	// GetAlerts fetches all the alerts that have changes since since.
	GetAlerts(ctx context.Context, since userconfig.ID) (*ConfigsResponse, error)
}

// New creates a new ConfigClient.
func New(cfg Config) (*ConfigDBClient, error) {

	if cfg.ConfigsAPIURL.URL == nil {
		return nil, errBadURL
	}

	client := &ConfigDBClient{
		URL:      cfg.ConfigsAPIURL.URL,
		Timeout:  cfg.ClientTimeout,
		TenantID: cfg.TenantID,
	}

	tlsConfig, err := cfg.TLS.GetTLSConfig()
	if err != nil {
		return nil, err
	}

	if tlsConfig != nil {
		client.TLSConfig = tlsConfig
	}
	return client, nil
}

// ConfigDBClient allows retrieving recording and alerting rules from the configs server.
type ConfigDBClient struct {
	URL       *url.URL
	Timeout   time.Duration
	TLSConfig *tls.Config
	// TenantID is the operator X-Scope-OrgID value injected into every
	// request made to the configs service. Must be set when the configs
	// service is run with authentication enabled, otherwise the /private/
	// endpoints will reject the client with HTTP 401.
	TenantID string
}

// GetRules implements Client
func (c ConfigDBClient) GetRules(ctx context.Context, since userconfig.ID) (map[string]userconfig.VersionedRulesConfig, error) {
	suffix := ""
	if since != 0 {
		suffix = fmt.Sprintf("?since=%d", since)
	}
	endpoint := fmt.Sprintf("%s/private/api/prom/configs/rules%s", c.URL.String(), suffix)
	var response *ConfigsResponse
	err := instrument.CollectedRequest(ctx, "GetRules", configsRequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		var err error
		response, err = doRequest(endpoint, c.Timeout, c.TLSConfig, c.TenantID, since)
		return err
	})
	if err != nil {
		return nil, err
	}
	configs := map[string]userconfig.VersionedRulesConfig{}
	for id, view := range response.Configs {
		cfg := view.GetVersionedRulesConfig()
		if cfg != nil {
			configs[id] = *cfg
		}
	}
	return configs, nil
}

// GetAlerts implements Client.
func (c ConfigDBClient) GetAlerts(ctx context.Context, since userconfig.ID) (*ConfigsResponse, error) {
	suffix := ""
	if since != 0 {
		suffix = fmt.Sprintf("?since=%d", since)
	}
	endpoint := fmt.Sprintf("%s/private/api/prom/configs/alertmanager%s", c.URL.String(), suffix)
	var response *ConfigsResponse
	err := instrument.CollectedRequest(ctx, "GetAlerts", configsRequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		var err error
		response, err = doRequest(endpoint, c.Timeout, c.TLSConfig, c.TenantID, since)
		return err
	})
	return response, err
}

func doRequest(endpoint string, timeout time.Duration, tlsConfig *tls.Config, tenantID string, since userconfig.ID) (*ConfigsResponse, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: timeout}
	if tlsConfig != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	req.Header.Set("User-Agent", fmt.Sprintf("Cortex/%s", version.Version))
	// The configs service /private/api/prom/configs/* endpoints return every
	// tenant's rules and alertmanager_config and now require an authenticated
	// operator identity. Propagate the configured tenant ID so the server's
	// HTTPAuthMiddleware accepts the request.
	if tenantID != "" {
		if err := user.InjectOrgIDIntoHTTPRequest(user.InjectOrgID(req.Context(), tenantID), req); err != nil {
			return nil, err
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Invalid response from configs server: %v", resp.StatusCode)
	}

	var config ConfigsResponse
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		level.Error(util_log.Logger).Log("msg", "configs: couldn't decode JSON body", "err", err)
		return nil, err
	}

	config.since = since
	return &config, nil
}

// ConfigsResponse is a response from server for Getuserconfig.
type ConfigsResponse struct {
	// The version since which these configs were changed
	since userconfig.ID

	// Configs maps user ID to their latest userconfig.View.
	Configs map[string]userconfig.View `json:"configs"`
}

// GetLatestConfigID returns the last config ID from a set of userconfig.
func (c ConfigsResponse) GetLatestConfigID() userconfig.ID {
	latest := c.since
	for _, config := range c.Configs {
		if config.ID > latest {
			latest = config.ID
		}
	}
	return latest
}
