package db

import (
	"context"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"

	"github.com/go-kit/log/level"
)

// traced adds log trace lines on each db call.
//
// IMPORTANT: Never log whole config objects. userconfig.Config.AlertmanagerConfig
// is raw tenant-supplied Alertmanager YAML and routinely contains third-party
// credentials (Slack webhook URLs, PagerDuty routing keys, SMTP passwords,
// webhook bearer tokens, etc.). The same applies to rules bodies. We therefore
// only log non-sensitive identifiers and sizes here.
type traced struct {
	d DB
}

// latestConfigID returns the maximum config ID in cfgs (zero if empty). It is
// safe to log and is useful as a "watermark" for the configdb poll path.
func latestConfigID(cfgs map[string]userconfig.View) userconfig.ID {
	var max userconfig.ID
	for _, v := range cfgs {
		if v.ID > max {
			max = v.ID
		}
	}
	return max
}

func latestRulesConfigID(cfgs map[string]userconfig.VersionedRulesConfig) userconfig.ID {
	var max userconfig.ID
	for _, v := range cfgs {
		if v.ID > max {
			max = v.ID
		}
	}
	return max
}

func (t traced) GetConfig(ctx context.Context, userID string) (cfg userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetConfig",
			"user", userID,
			"config_id", cfg.ID,
			"err", err)
	}()
	return t.d.GetConfig(ctx, userID)
}

func (t traced) SetConfig(ctx context.Context, userID string, cfg userconfig.Config) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "SetConfig",
			"user", userID,
			"rule_files", len(cfg.RulesConfig.Files),
			"template_files", len(cfg.TemplateFiles),
			"am_config_bytes", len(cfg.AlertmanagerConfig),
			"err", err)
	}()
	return t.d.SetConfig(ctx, userID, cfg)
}

func (t traced) GetAllConfigs(ctx context.Context) (cfgs map[string]userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetAllConfigs",
			"tenants", len(cfgs),
			"latest_config_id", latestConfigID(cfgs),
			"err", err)
	}()
	return t.d.GetAllConfigs(ctx)
}

func (t traced) GetConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetConfigs",
			"since", since,
			"tenants", len(cfgs),
			"latest_config_id", latestConfigID(cfgs),
			"err", err)
	}()
	return t.d.GetConfigs(ctx, since)
}

func (t traced) DeactivateConfig(ctx context.Context, userID string) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "DeactivateConfig", "user", userID, "err", err)
	}()
	return t.d.DeactivateConfig(ctx, userID)
}

func (t traced) RestoreConfig(ctx context.Context, userID string) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "RestoreConfig", "user", userID, "err", err)
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
		level.Debug(util_log.Logger).Log("msg", "GetRulesConfig",
			"user", userID,
			"config_id", cfg.ID,
			"rule_files", len(cfg.Config.Files),
			"err", err)
	}()
	return t.d.GetRulesConfig(ctx, userID)
}

func (t traced) SetRulesConfig(ctx context.Context, userID string, oldCfg, newCfg userconfig.RulesConfig) (updated bool, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "SetRulesConfig",
			"user", userID,
			"old_rule_files", len(oldCfg.Files),
			"new_rule_files", len(newCfg.Files),
			"updated", updated,
			"err", err)
	}()
	return t.d.SetRulesConfig(ctx, userID, oldCfg, newCfg)
}

func (t traced) GetAllRulesConfigs(ctx context.Context) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetAllRulesConfigs",
			"tenants", len(cfgs),
			"latest_config_id", latestRulesConfigID(cfgs),
			"err", err)
	}()
	return t.d.GetAllRulesConfigs(ctx)
}

func (t traced) GetRulesConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetRulesConfigs",
			"since", since,
			"tenants", len(cfgs),
			"latest_config_id", latestRulesConfigID(cfgs),
			"err", err)
	}()
	return t.d.GetRulesConfigs(ctx, since)
}
