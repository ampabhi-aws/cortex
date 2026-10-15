package db

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/cortexproject/cortex/pkg/configs/db/memory"
	"github.com/cortexproject/cortex/pkg/configs/db/postgres"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

// Config configures the database.
type Config struct {
	URI           string `yaml:"uri"`
	MigrationsDir string `yaml:"migrations_dir"`
	PasswordFile  string `yaml:"password_file"`

	// Allow injection of mock DBs for unit testing.
	Mock DB `yaml:"-"`
}

// MarshalYAML implements yaml.Marshaler so that any password embedded in
// the DSN (uri) is redacted when the config is dumped (e.g. via /config).
func (cfg Config) MarshalYAML() (interface{}, error) {
	return struct {
		URI           string `yaml:"uri"`
		MigrationsDir string `yaml:"migrations_dir"`
		PasswordFile  string `yaml:"password_file"`
	}{
		URI:           maskURIPassword(cfg.URI),
		MigrationsDir: cfg.MigrationsDir,
		PasswordFile:  cfg.PasswordFile,
	}, nil
}

// maskURIPassword returns the URI with the password portion of any embedded
// userinfo replaced with "********". If the URI cannot be parsed or contains
// no inline password, it is returned unchanged.
func maskURIPassword(uri string) string {
	if uri == "" {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil || u.User == nil {
		return uri
	}
	if _, set := u.User.Password(); !set {
		return uri
	}
	u.User = url.UserPassword(u.User.Username(), "********")
	return u.String()
}

// RegisterFlags adds the flags required to configure this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.StringVar(&cfg.URI, "configs.database.uri", "postgres://postgres@configs-db.weave.local/configs?sslmode=disable", "URI where the database can be found (for dev you can use memory://)")
	f.StringVar(&cfg.MigrationsDir, "configs.database.migrations-dir", "", "Path where the database migration files can be found")
	f.StringVar(&cfg.PasswordFile, "configs.database.password-file", "", "File containing password (username goes in URI)")
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
