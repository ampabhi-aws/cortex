package db

import (
	"context"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"

	"github.com/go-kit/log/level"
)

// traced adds log trace lines on each db call.
//
// Trace lines intentionally contain only non-sensitive identifiers (user IDs,
// config IDs, result counts, errors). Tenant configuration payloads
// (userconfig.Config / userconfig.View / userconfig.RulesConfig) are never
// rendered into logs here because they carry Alertmanager notification
// secrets (SMTP passwords, Slack webhook URLs, PagerDuty routing keys,
// bearer tokens, etc.). See CWE-215.
type traced struct {
	d DB
}

func (t traced) GetConfig(ctx context.Context, userID string) (cfg userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetConfig",
			"user", userID, "config_id", cfg.ID, "err", err)
	}()
	return t.d.GetConfig(ctx, userID)
}

func (t traced) SetConfig(ctx context.Context, userID string, cfg userconfig.Config) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "SetConfig",
			"user", userID, "err", err)
	}()
	return t.d.SetConfig(ctx, userID, cfg)
}

func (t traced) GetAllConfigs(ctx context.Context) (cfgs map[string]userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetAllConfigs",
			"count", len(cfgs), "err", err)
	}()
	return t.d.GetAllConfigs(ctx)
}

func (t traced) GetConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.View, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetConfigs",
			"since", since, "count", len(cfgs), "err", err)
	}()
	return t.d.GetConfigs(ctx, since)
}

func (t traced) DeactivateConfig(ctx context.Context, userID string) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "DeactivateConfig",
			"user", userID, "err", err)
	}()
	return t.d.DeactivateConfig(ctx, userID)
}

func (t traced) RestoreConfig(ctx context.Context, userID string) (err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "RestoreConfig",
			"user", userID, "err", err)
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
			"user", userID, "config_id", cfg.ID, "err", err)
	}()
	return t.d.GetRulesConfig(ctx, userID)
}

func (t traced) SetRulesConfig(ctx context.Context, userID string, oldCfg, newCfg userconfig.RulesConfig) (updated bool, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "SetRulesConfig",
			"user", userID, "updated", updated, "err", err)
	}()
	return t.d.SetRulesConfig(ctx, userID, oldCfg, newCfg)
}

func (t traced) GetAllRulesConfigs(ctx context.Context) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetAllRulesConfigs",
			"count", len(cfgs), "err", err)
	}()
	return t.d.GetAllRulesConfigs(ctx)
}

func (t traced) GetRulesConfigs(ctx context.Context, since userconfig.ID) (cfgs map[string]userconfig.VersionedRulesConfig, err error) {
	defer func() {
		level.Debug(util_log.Logger).Log("msg", "GetRulesConfigs",
			"since", since, "count", len(cfgs), "err", err)
	}()
	return t.d.GetRulesConfigs(ctx, since)
}
