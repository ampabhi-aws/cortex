package configdb

import (
	"context"
	"errors"
	"sync"

	"github.com/cortexproject/cortex/pkg/alertmanager/alertspb"
	"github.com/cortexproject/cortex/pkg/configs/client"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

const (
	Name = "configdb"
)

var (
	errReadOnly = errors.New("configdb alertmanager config storage is read-only")
	errState    = errors.New("configdb alertmanager storage does not support state persistency")
)

// Store is a concrete implementation of RuleStore that sources rules from the config service.
//
// The mutable cache (alertConfigs and the since cursor) is guarded by mtx
// because reloadConfigs is reached from many goroutines in parallel: the
// unauthenticated admin endpoint fans out via concurrency.ForEachUser with
// fetchConcurrency=16, and the Alertmanager poll loop runs on the same
// instance. Without the mutex, concurrent writes to the Go map are detected
// by the runtime and abort the whole process with an unrecoverable fatal
// error that bypasses recover() and the HTTP server panic middleware.
type Store struct {
	configClient client.Client

	mtx          sync.Mutex
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
	// Snapshot `since` under the lock so we don't observe a torn read.
	c.mtx.Lock()
	since := c.since
	c.mtx.Unlock()

	configs, err := c.configClient.GetAlerts(ctx, since)
	if err != nil {
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	for user, cfg := range configs.Configs {
		if cfg.IsDeleted() {
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

	// Only move `since` forward: a concurrent reload may already have
	// advanced it past this response's latest id.
	if id := configs.GetLatestConfigID(); id > c.since {
		c.since = id
	}

	// Return a copy so callers can never observe or mutate the live cache,
	// which would race with subsequent reloads.
	out := make(map[string]alertspb.AlertConfigDesc, len(c.alertConfigs))
	for k, v := range c.alertConfigs {
		out[k] = v
	}
	return out, nil
}
