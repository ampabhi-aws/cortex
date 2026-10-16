package db

import (
	"context"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"

	"github.com/go-kit/log/level"
)

// traced adds log trace lines on each db call.
//
// IMPORTANT: trace must never log full configuration objects. Tenant
// configurations (e.g. userconfig.Config.AlertmanagerConfig) can contain
// third-party notification secrets such as Slack webhook URLs, PagerDuty
// routing keys, and SMTP passwords in raw YAML. Logging whole configs with
// %#v (or any representation that includes AlertmanagerConfig / template
// bodies) would copy those secrets in cleartext into the service log.
// Only operation name, non-sensitive identifiers (userID, config ID), and
// error values are safe to log here.
type traced struct {
	d DB
}

func (t traced) trace(name string, keyvals ...interface{}) {
	args := make([]interface{}, 0, len(keyvals)+2)
	args = append(args, "msg", name)
	args = append(args, keyvals...)
	level.Debug(util_log.Logger).Log(args...)
}

func (t traced) GetConfig(ctx context.Context, userID string) (cfg userconfig.View, err error) {
	defer func() { t.trace("GetConfig", "userID", userID, "configID", cfg.ID, "err", err) }()
	return t.d.GetConfig(ctx, userID)
}

func (t traced) SetConfig(ctx context.Context, userID string, cfg userconfig.Config) (err error) {
	// Do not log cfg: it embeds Alertmanager YAML with third-party secrets.
	defer func() { t.trace("SetConfig", "userID", userID, "err", err) }()
	return t.d.SetConfig(ctx, userID, cfg)
}

func (t traced) GetAllConfigs(ctx context.Context) (cfgs map[string]userconfig.View, err error) {
	// Do not log cfgs: it is the all-tenant map and includes Alertmanager secrets.
	defer func() { t.trace("GetAllConfigs", "count", len(cfgs), "err", err) }()
	return t.d.GetAllConfigs(ctx)
}

func (t traced) GetConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.View, err error) {
	// Do not log cfgs: it is the all-tenant map and includes Alertmanager secrets.
	defer func() { t.trace("GetConfigs", "since", since, "count", len(cfgs), "err", err) }()
	return t.d.GetConfigs(ctx, since)
}

func (t traced) DeactivateConfig(ctx context.Context, userID string) (err error) {
	defer func() { t.trace("DeactivateConfig", "userID", userID, "err", err) }()
	return t.d.DeactivateConfig(ctx, userID)
}

func (t traced) RestoreConfig(ctx context.Context, userID string) (err error) {
	defer func() { t.trace("RestoreConfig", "userID", userID, "err", err) }()
	return t.d.RestoreConfig(ctx, userID)
}

func (t traced) Close() (err error) {
	defer func() { t.trace("Close", "err", err) }()
	return t.d.Close()
}

func (t traced) GetRulesConfig(ctx context.Context, userID string) (cfg userconfig.VersionedRulesConfig, err error) {
	// Do not log the full RulesConfig; log only identifiers and error.
	defer func() { t.trace("GetRulesConfig", "userID", userID, "configID", cfg.ID, "err", err) }()
	return t.d.GetRulesConfig(ctx, userID)
}

func (t traced) SetRulesConfig(ctx context.Context, userID string, oldCfg, newCfg userconfig.RulesConfig) (updated bool, err error) {
	// Do not log oldCfg/newCfg: rules bodies may contain sensitive expressions
	// or template content; log only identifiers, update outcome, and error.
	defer func() { t.trace("SetRulesConfig", "userID", userID, "updated", updated, "err", err) }()
	return t.d.SetRulesConfig(ctx, userID, oldCfg, newCfg)
}

func (t traced) GetAllRulesConfigs(ctx context.Context) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() { t.trace("GetAllRulesConfigs", "count", len(cfgs), "err", err) }()
	return t.d.GetAllRulesConfigs(ctx)
}

func (t traced) GetRulesConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() { t.trace("GetRulesConfigs", "since", since, "count", len(cfgs), "err", err) }()
	return t.d.GetRulesConfigs(ctx, since)
}
