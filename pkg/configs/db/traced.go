package db

import (
	"context"
	"fmt"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"

	"github.com/go-kit/log/level"
)

// traced adds log trace lines on each db call.
//
// NOTE: trace deliberately logs only non-sensitive identifiers (operation
// name, userID, config IDs, counts, error). It must never log
// userconfig.Config or userconfig.View values, because those carry tenants'
// raw Alertmanager YAML and template files, which contain notification
// credentials (SMTP passwords, Slack/PagerDuty webhook secrets, etc.).
type traced struct {
	d DB
}

func (t traced) trace(name string, args ...interface{}) {
	level.Debug(util_log.Logger).Log("msg", fmt.Sprintf("%s: %v", name, args))
}

func (t traced) GetConfig(ctx context.Context, userID string) (cfg userconfig.View, err error) {
	defer func() { t.trace("GetConfig", userID, err) }()
	return t.d.GetConfig(ctx, userID)
}

func (t traced) SetConfig(ctx context.Context, userID string, cfg userconfig.Config) (err error) {
	defer func() { t.trace("SetConfig", userID, err) }()
	return t.d.SetConfig(ctx, userID, cfg)
}

func (t traced) GetAllConfigs(ctx context.Context) (cfgs map[string]userconfig.View, err error) {
	defer func() { t.trace("GetAllConfigs", len(cfgs), err) }()
	return t.d.GetAllConfigs(ctx)
}

func (t traced) GetConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.View, err error) {
	defer func() { t.trace("GetConfigs", since, len(cfgs), err) }()
	return t.d.GetConfigs(ctx, since)
}

func (t traced) DeactivateConfig(ctx context.Context, userID string) (err error) {
	defer func() { t.trace("DeactivateConfig", userID, err) }()
	return t.d.DeactivateConfig(ctx, userID)
}

func (t traced) RestoreConfig(ctx context.Context, userID string) (err error) {
	defer func() { t.trace("RestoreConfig", userID, err) }()
	return t.d.RestoreConfig(ctx, userID)
}

func (t traced) Close() (err error) {
	defer func() { t.trace("Close", err) }()
	return t.d.Close()
}

func (t traced) GetRulesConfig(ctx context.Context, userID string) (cfg userconfig.VersionedRulesConfig, err error) {
	defer func() { t.trace("GetRulesConfig", userID, err) }()
	return t.d.GetRulesConfig(ctx, userID)
}

func (t traced) SetRulesConfig(ctx context.Context, userID string, oldCfg, newCfg userconfig.RulesConfig) (updated bool, err error) {
	defer func() { t.trace("SetRulesConfig", userID, updated, err) }()
	return t.d.SetRulesConfig(ctx, userID, oldCfg, newCfg)
}

func (t traced) GetAllRulesConfigs(ctx context.Context) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() { t.trace("GetAllRulesConfigs", len(cfgs), err) }()
	return t.d.GetAllRulesConfigs(ctx)
}

func (t traced) GetRulesConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() { t.trace("GetRulesConfigs", since, len(cfgs), err) }()
	return t.d.GetRulesConfigs(ctx, since)
}
