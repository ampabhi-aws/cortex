package configdb

import (
	"context"
	"errors"

	"github.com/go-kit/log/level"
	amconfig "github.com/prometheus/alertmanager/config"

	"github.com/cortexproject/cortex/pkg/alertmanager/alertcfg"
	"github.com/cortexproject/cortex/pkg/alertmanager/alertspb"
	"github.com/cortexproject/cortex/pkg/configs/client"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

const (
	Name = "configdb"
)

var (
	errReadOnly = errors.New("configdb alertmanager config storage is read-only")
	errState    = errors.New("configdb alertmanager storage does not support state persistency")
)

// Store is a concrete implementation of RuleStore that sources rules from the config service
type Store struct {
	configClient client.Client
	since        userconfig.ID
	alertConfigs map[string]alertspb.AlertConfigDesc
}

// NewStore constructs a Store
func NewStore(c client.Client) *Store {
	return &Store{
		configClient: c,
		since:        0,
		alertConfigs: make(map[string]alertspb.AlertConfigDesc),
	}
}

// ListAllUsers implements alertstore.AlertStore.
func (c *Store) ListAllUsers(ctx context.Context) ([]string, error) {
	configs, err := c.reloadConfigs(ctx)
	if err != nil {
		return nil, err
	}

	userIDs := make([]string, 0, len(configs))
	for userID := range configs {
		userIDs = append(userIDs, userID)
	}

	return userIDs, nil
}

// GetAlertConfigs implements alertstore.AlertStore.
func (c *Store) GetAlertConfigs(ctx context.Context, userIDs []string) (map[string]alertspb.AlertConfigDesc, error) {
	// Refresh the local state.
	configs, err := c.reloadConfigs(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make(map[string]alertspb.AlertConfigDesc, len(userIDs))
	for _, userID := range userIDs {
		if cfg, ok := configs[userID]; ok {
			filtered[userID] = cfg
		}
	}

	return filtered, nil
}

// GetAlertConfig implements alertstore.AlertStore.
func (c *Store) GetAlertConfig(ctx context.Context, user string) (alertspb.AlertConfigDesc, error) {
	// Refresh the local state.
	configs, err := c.reloadConfigs(ctx)
	if err != nil {
		return alertspb.AlertConfigDesc{}, err
	}

	cfg, exists := configs[user]
	if !exists {
		return alertspb.AlertConfigDesc{}, alertspb.ErrNotFound
	}

	return cfg, nil
}

// SetAlertConfig implements alertstore.AlertStore.
func (c *Store) SetAlertConfig(ctx context.Context, cfg alertspb.AlertConfigDesc) error {
	return errReadOnly
}

// DeleteAlertConfig implements alertstore.AlertStore.
func (c *Store) DeleteAlertConfig(ctx context.Context, user string) error {
	return errReadOnly
}

// ListUsersWithFullState implements alertstore.AlertStore.
func (c *Store) ListUsersWithFullState(ctx context.Context) ([]string, error) {
	return nil, errState
}

// GetFullState implements alertstore.AlertStore.
func (c *Store) GetFullState(ctx context.Context, user string) (alertspb.FullStateDesc, error) {
	return alertspb.FullStateDesc{}, errState
}

// SetFullState implements alertstore.AlertStore.
func (c *Store) SetFullState(ctx context.Context, user string, cfg alertspb.FullStateDesc) error {
	return errState
}

// DeleteFullState implements alertstore.AlertStore.
func (c *Store) DeleteFullState(ctx context.Context, user string) error {
	return errState
}

func (c *Store) reloadConfigs(ctx context.Context) (map[string]alertspb.AlertConfigDesc, error) {
	configs, err := c.configClient.GetAlerts(ctx, c.since)
	if err != nil {
		return nil, err
	}

	for user, cfg := range configs.Configs {
		if cfg.IsDeleted() {
			delete(c.alertConfigs, user)
			continue
		}

		// Defense in depth: the write path through the configs service API is
		// supposed to apply the `*_file` denylist, but older/concurrent writers
		// may have persisted a tenant YAML before the hardened validator was in
		// place. Re-apply the shared validator here so we never surface a
		// config that would let a tenant read arbitrary host files and exfil
		// them through a notifier (CVE-2021-31232 / CVE-2021-36157). On error,
		// drop the config for this tenant rather than loading an unsafe one.
		if err := validateRawAlertmanagerConfig(cfg.Config.AlertmanagerConfig); err != nil {
			level.Warn(util_log.Logger).Log("msg", "configdb: dropping tenant Alertmanager config that failed validation", "user", user, "err", err)
			delete(c.alertConfigs, user)
			continue
		}

		var templates []*alertspb.TemplateDesc
		for fn, template := range cfg.Config.TemplateFiles {
			templates = append(templates, &alertspb.TemplateDesc{
				Filename: fn,
				Body:     template,
			})
		}

		c.alertConfigs[user] = alertspb.AlertConfigDesc{
			User:      user,
			RawConfig: cfg.Config.AlertmanagerConfig,
			Templates: templates,
		}
	}

	c.since = configs.GetLatestConfigID()

	return c.alertConfigs, nil
}

// validateRawAlertmanagerConfig applies the hardened Alertmanager validator to
// a tenant-supplied YAML. Empty configs are allowed (they translate to the
// fallback config). Returns nil if the config is safe to load.
func validateRawAlertmanagerConfig(raw string) error {
	if raw == "" {
		return nil
	}
	amCfg, err := amconfig.Load(raw)
	if err != nil {
		return err
	}
	if err := alertcfg.Validate(amCfg); err != nil {
		return err
	}
	for _, name := range amCfg.Templates {
		if err := alertcfg.ValidateTemplateFilename(name); err != nil {
			return err
		}
	}
	return nil
}
