package db

import (
	"context"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"

	"github.com/go-kit/log/level"
)

// traced adds log trace lines on each db call.
//
// Important: trace lines must never include the raw per-tenant Alertmanager
// configuration, rules bodies or notification templates — those are credential
// grade (Slack tokens, PagerDuty/OpsGenie/VictorOps keys, webhook URLs,
// smtp_auth_password, …) and get shipped to shared log aggregators. Each
// method below only logs identifiers and sizes.
type traced struct {
	d DB
}

func (t traced) GetConfig(ctx context.Context, userID string) (cfg userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "GetConfig",
			"userID", userID,
			"id", int(cfg.ID),
			"rules_files", len(cfg.Config.RulesConfig.Files),
			"template_files", len(cfg.Config.TemplateFiles),
			"am_config_bytes", len(cfg.Config.AlertmanagerConfig),
			"err", err,
		)
	}()
	return t.d.GetConfig(ctx, userID)
}

func (t traced) SetConfig(ctx context.Context, userID string, cfg userconfig.Config) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "SetConfig",
			"userID", userID,
			"rules_files", len(cfg.RulesConfig.Files),
			"template_files", len(cfg.TemplateFiles),
			"am_config_bytes", len(cfg.AlertmanagerConfig),
			"err", err,
		)
	}()
	return t.d.SetConfig(ctx, userID, cfg)
}

func (t traced) GetAllConfigs(ctx context.Context) (cfgs map[string]userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "GetAllConfigs",
			"count", len(cfgs),
			"err", err,
		)
	}()
	return t.d.GetAllConfigs(ctx)
}

func (t traced) GetConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "GetConfigs",
			"since", int(since),
			"count", len(cfgs),
			"err", err,
		)
	}()
	return t.d.GetConfigs(ctx, since)
}

func (t traced) DeactivateConfig(ctx context.Context, userID string) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "DeactivateConfig",
			"userID", userID,
			"err", err,
		)
	}()
	return t.d.DeactivateConfig(ctx, userID)
}

func (t traced) RestoreConfig(ctx context.Context, userID string) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "RestoreConfig",
			"userID", userID,
			"err", err,
		)
	}()
	return t.d.RestoreConfig(ctx, userID)
}

func (t traced) Close() (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "Close", "err", err)
	}()
	return t.d.Close()
}

func (t traced) GetRulesConfig(ctx context.Context, userID string) (cfg userconfig.VersionedRulesConfig, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "GetRulesConfig",
			"userID", userID,
			"id", int(cfg.ID),
			"rules_files", len(cfg.Config.Files),
			"err", err,
		)
	}()
	return t.d.GetRulesConfig(ctx, userID)
}

func (t traced) SetRulesConfig(ctx context.Context, userID string, oldCfg, newCfg userconfig.RulesConfig) (updated bool, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "SetRulesConfig",
			"userID", userID,
			"old_rules_files", len(oldCfg.Files),
			"new_rules_files", len(newCfg.Files),
			"updated", updated,
			"err", err,
		)
	}()
	return t.d.SetRulesConfig(ctx, userID, oldCfg, newCfg)
}

func (t traced) GetAllRulesConfigs(ctx context.Context) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "GetAllRulesConfigs",
			"count", len(cfgs),
			"err", err,
		)
	}()
	return t.d.GetAllRulesConfigs(ctx)
}

func (t traced) GetRulesConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log(
			"msg", "GetRulesConfigs",
			"since", int(since),
			"count", len(cfgs),
			"err", err,
		)
	}()
	return t.d.GetRulesConfigs(ctx, since)
}
