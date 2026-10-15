package db

import (
	"context"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"

	"github.com/go-kit/log/level"
)

// traced adds log trace lines on each db call.
//
// NOTE: trace lines deliberately omit configuration payloads. Tenant
// configurations contain third-party notification credentials (Slack
// webhooks, PagerDuty/OpsGenie keys, SMTP passwords, ...) in their raw
// Alertmanager YAML, so logging the Config/View values -- including via
// Go's %#v / %+v verbs -- would leak those secrets to anyone with access
// to the process logs. We log only non-sensitive identifiers and
// outcomes (operation name, user ID, config ID, counts and the error).
type traced struct {
	d DB
}

// trace emits a single key/value debug log record with no configuration
// payload. Callers pass the operation name plus any additional
// non-sensitive key/value pairs they want to include.
func (t traced) trace(op string, keyvals ...interface{}) {
	kv := make([]interface{}, 0, 2+len(keyvals))
	kv = append(kv, "msg", op)
	kv = append(kv, keyvals...)
	_ = level.Debug(util_log.Logger).Log(kv...)
}

func (t traced) GetConfig(ctx context.Context, userID string) (cfg userconfig.View, err error) {
	defer func() { t.trace("GetConfig", "user", userID, "id", cfg.ID, "err", err) }()
	return t.d.GetConfig(ctx, userID)
}

func (t traced) SetConfig(ctx context.Context, userID string, cfg userconfig.Config) (err error) {
	defer func() {
		t.trace("SetConfig",
			"user", userID,
			"alertmanager_config_bytes", len(cfg.AlertmanagerConfig),
			"template_files", len(cfg.TemplateFiles),
			"rule_files", len(cfg.RulesConfig.Files),
			"err", err)
	}()
	return t.d.SetConfig(ctx, userID, cfg)
}

func (t traced) GetAllConfigs(ctx context.Context) (cfgs map[string]userconfig.View, err error) {
	defer func() { t.trace("GetAllConfigs", "count", len(cfgs), "err", err) }()
	return t.d.GetAllConfigs(ctx)
}

func (t traced) GetConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.View, err error) {
	defer func() { t.trace("GetConfigs", "since", since, "count", len(cfgs), "err", err) }()
	return t.d.GetConfigs(ctx, since)
}

func (t traced) DeactivateConfig(ctx context.Context, userID string) (err error) {
	defer func() { t.trace("DeactivateConfig", "user", userID, "err", err) }()
	return t.d.DeactivateConfig(ctx, userID)
}

func (t traced) RestoreConfig(ctx context.Context, userID string) (err error) {
	defer func() { t.trace("RestoreConfig", "user", userID, "err", err) }()
	return t.d.RestoreConfig(ctx, userID)
}

func (t traced) Close() (err error) {
	defer func() { t.trace("Close", "err", err) }()
	return t.d.Close()
}

func (t traced) GetRulesConfig(ctx context.Context, userID string) (cfg userconfig.VersionedRulesConfig, err error) {
	defer func() {
		t.trace("GetRulesConfig", "user", userID, "id", cfg.ID, "rule_files", len(cfg.Config.Files), "err", err)
	}()
	return t.d.GetRulesConfig(ctx, userID)
}

func (t traced) SetRulesConfig(ctx context.Context, userID string, oldCfg, newCfg userconfig.RulesConfig) (updated bool, err error) {
	defer func() {
		t.trace("SetRulesConfig",
			"user", userID,
			"old_rule_files", len(oldCfg.Files),
			"new_rule_files", len(newCfg.Files),
			"updated", updated,
			"err", err)
	}()
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
