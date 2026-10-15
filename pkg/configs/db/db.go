package db

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/go-kit/log/level"

	"github.com/cortexproject/cortex/pkg/configs/db/memory"
	"github.com/cortexproject/cortex/pkg/configs/db/postgres"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

// insecurePostgresSSLModes are the lib/pq sslmode values that do not
// guarantee a TLS-protected session to the database. The configs DB stores
// tenant Alertmanager configurations (including third-party notification
// credentials), rule files and notification templates, so operators must
// terminate the connection with TLS. We warn loudly at startup when any of
// these modes is configured; we do not refuse to start in order to preserve
// backwards compatibility with existing deployments.
var insecurePostgresSSLModes = map[string]struct{}{
	"disable": {},
	"allow":   {},
	"prefer":  {},
}

// Config configures the database.
type Config struct {
	URI           string `yaml:"uri"`
	MigrationsDir string `yaml:"migrations_dir"`
	PasswordFile  string `yaml:"password_file"`

	// Allow injection of mock DBs for unit testing.
	Mock DB `yaml:"-"`
}

// RegisterFlags adds the flags required to configure this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.StringVar(&cfg.URI, "configs.database.uri", "postgres://postgres@configs-db.weave.local/configs?sslmode=disable", "URI where the database can be found (for dev you can use memory://). The configs DB stores tenant Alertmanager configurations and other secrets; set sslmode=verify-full (with sslrootcert) on the Postgres URI so the connection is TLS-protected.")
	f.StringVar(&cfg.MigrationsDir, "configs.database.migrations-dir", "", "Path where the database migration files can be found")
	f.StringVar(&cfg.PasswordFile, "configs.database.password-file", "", "File containing password (username goes in URI)")
}

// warnIfInsecurePostgresURI emits a loud startup warning when the Postgres
// URI selects a non-TLS sslmode (disable, allow or prefer). It is a no-op for
// non-postgres schemes. The warning intentionally does not block startup to
// avoid breaking existing operator deployments.
func warnIfInsecurePostgresURI(u *url.URL) {
	if u == nil || u.Scheme != "postgres" {
		return
	}
	mode := u.Query().Get("sslmode")
	if mode == "" {
		// lib/pq defaults to sslmode=require when unset, which negotiates
		// TLS but does not verify the server certificate. Still better than
		// cleartext, so do not warn here.
		return
	}
	if _, insecure := insecurePostgresSSLModes[mode]; insecure {
		level.Warn(util_log.Logger).Log(
			"msg", "configs database connection is NOT TLS-protected; tenant Alertmanager configurations (including third-party credentials), rule files and the database password will cross the network in cleartext. Set sslmode=verify-full with a trusted sslrootcert on -configs.database.uri.",
			"sslmode", mode,
		)
	}
}

// DB is the interface for the database.
type DB interface {
	// GetRulesConfig gets the user's ruler config
	GetRulesConfig(ctx context.Context, userID string) (userconfig.VersionedRulesConfig, error)

	// SetRulesConfig does a compare-and-swap (CAS) on the user's rules config.
	// `oldConfig` must precisely match the current config in order to change the config to `newConfig`.
	// Will return `true` if the config was updated, `false` otherwise.
	SetRulesConfig(ctx context.Context, userID string, oldConfig, newConfig userconfig.RulesConfig) (bool, error)

	// GetAllRulesConfigs gets all of the ruler configs
	GetAllRulesConfigs(ctx context.Context) (map[string]userconfig.VersionedRulesConfig, error)

	// GetRulesConfigs gets all of the configs that have been added or have
	// changed since the provided config.
	GetRulesConfigs(ctx context.Context, since userconfig.ID) (map[string]userconfig.VersionedRulesConfig, error)

	GetConfig(ctx context.Context, userID string) (userconfig.View, error)
	SetConfig(ctx context.Context, userID string, cfg userconfig.Config) error

	GetAllConfigs(ctx context.Context) (map[string]userconfig.View, error)
	GetConfigs(ctx context.Context, since userconfig.ID) (map[string]userconfig.View, error)

	DeactivateConfig(ctx context.Context, userID string) error
	RestoreConfig(ctx context.Context, userID string) error

	Close() error
}

// New creates a new database.
func New(cfg Config) (DB, error) {
	if cfg.Mock != nil {
		return cfg.Mock, nil
	}

	u, err := url.Parse(cfg.URI)
	if err != nil {
		return nil, err
	}

	warnIfInsecurePostgresURI(u)

	if len(cfg.PasswordFile) != 0 {
		if u.User == nil {
			return nil, fmt.Errorf("--database.password-file requires username in --database.uri")
		}
		passwordBytes, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("Could not read database password file: %v", err)
		}
		u.User = url.UserPassword(u.User.Username(), string(passwordBytes))
	}

	var d DB
	switch u.Scheme {
	case "memory":
		d, err = memory.New(u.String(), cfg.MigrationsDir)
	case "postgres":
		d, err = postgres.New(u.String(), cfg.MigrationsDir)
	default:
		return nil, fmt.Errorf("Unknown database type: %s", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	return traced{timed{d}}, nil
}
