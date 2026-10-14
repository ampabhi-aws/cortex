package db

import (
	"context"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"

	"github.com/go-kit/log/level"
)

// traced adds log trace lines on each db call
type traced struct {
	d DB
}

// trace emits a debug log line with the method name and the supplied
// non-sensitive key/value pairs. Callers must never pass raw
// userconfig.Config / userconfig.View values (which embed
// AlertmanagerConfig YAML and TemplateFiles that routinely contain
// third-party credentials); they should instead pass only identifiers,
// sizes, and errors.
func (t traced) trace(name string, keyvals ...interface{}) {
	args := make([]interface{}, 0, len(keyvals)+2)
	args = append(args, "msg", name)
	args = append(args, keyvals...)
	level.Debug(util_log.Logger).Log(args...)
}

func (t traced) GetConfig(ctx context.Context, userID string) (cfg userconfig.View, err error) {
	defer func() {
		t.trace("GetConfig",
			"userID", userID,
			"configID", cfg.ID,
			"alertmanagerConfigBytes", len(cfg.Config.AlertmanagerConfig),
			"templateFiles", len(cfg.Config.TemplateFiles),
			"err", err,
		)
	}()
	return t.d.GetConfig(ctx, userID)
}

func (t traced) SetConfig(ctx context.Context, userID string, cfg userconfig.Config) (err error) {
	defer func() {
		t.trace("SetConfig",
			"userID", userID,
			"alertmanagerConfigBytes", len(cfg.AlertmanagerConfig),
			"templateFiles", len(cfg.TemplateFiles),
			"err", err,
		)
	}()
	return t.d.SetConfig(ctx, userID, cfg)
}

func (t traced) GetAllConfigs(ctx context.Context) (cfgs map[string]userconfig.View, err error) {
	defer func() { t.trace("GetAllConfigs", "configs", len(cfgs), "err", err) }()
	return t.d.GetAllConfigs(ctx)
}

func (t traced) GetConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.View, err error) {
	defer func() { t.trace("GetConfigs", "since", since, "configs", len(cfgs), "err", err) }()
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
	defer func() {
		t.trace("GetRulesConfig",
			"userID", userID,
			"configID", cfg.ID,
			"ruleFiles", len(cfg.Config.Files),
			"err", err,
		)
	}()
	return t.d.GetRulesConfig(ctx, userID)
}

func (t traced) SetRulesConfig(ctx context.Context, userID string, oldCfg, newCfg userconfig.RulesConfig) (updated bool, err error) {
	defer func() {
		t.trace("SetRulesConfig",
			"userID", userID,
			"oldRuleFiles", len(oldCfg.Files),
			"newRuleFiles", len(newCfg.Files),
			"updated", updated,
			"err", err,
		)
	}()
	return t.d.SetRulesConfig(ctx, userID, oldCfg, newCfg)
}

func (t traced) GetAllRulesConfigs(ctx context.Context) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() { t.trace("GetAllRulesConfigs", "configs", len(cfgs), "err", err) }()
	return t.d.GetAllRulesConfigs(ctx)
}

func (t traced) GetRulesConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() { t.trace("GetRulesConfigs", "since", since, "configs", len(cfgs), "err", err) }()
	return t.d.GetRulesConfigs(ctx, since)
}
