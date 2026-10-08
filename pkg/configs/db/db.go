package db

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/cortexproject/cortex/pkg/configs/db/memory"
	"github.com/cortexproject/cortex/pkg/configs/db/postgres"
	"github.com/cortexproject/cortex/pkg/configs/userconfig"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// defaultURI is the default DSN registered for configs.database.uri. It uses
// sslmode=verify-full so a misconfigured deployment fails closed rather than
// silently transmitting the DB password and tenant configs in cleartext.
const defaultURI = "postgres://postgres@configs-db.weave.local/configs?sslmode=verify-full"

// Config configures the database.
type Config struct {
	// URI is a flagext.URLValue so that any embedded password is redacted when
	// the live config is marshalled (e.g. by the unauthenticated /config HTTP
	// endpoint). See pkg/util/flagext/url.go.
	URI           flagext.URLValue `yaml:"uri"`
	MigrationsDir string           `yaml:"migrations_dir"`
	PasswordFile  string           `yaml:"password_file"`

	// Allow injection of mock DBs for unit testing.
	Mock DB `yaml:"-"`
}

// RegisterFlags adds the flags required to configure this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	// Seed the default so URI.URL is non-nil and MarshalYAML redacts any
	// embedded password when the live config is served.
	if err := cfg.URI.Set(defaultURI); err != nil {
		// defaultURI is a constant, so this cannot fail at runtime.
		panic(fmt.Sprintf("invalid default configs.database.uri: %v", err))
	}
	f.Var(&cfg.URI, "configs.database.uri", "URI where the database can be found (for dev you can use memory://)")
	f.StringVar(&cfg.MigrationsDir, "configs.database.migrations-dir", "", "Path where the database migration files can be found")
	f.StringVar(&cfg.PasswordFile, "configs.database.password-file", "", "File containing password (username goes in URI)")
}

// Validate validates the configs database configuration. It rejects insecure
// sslmode settings when a database password is configured (either inline in
// the URI or via PasswordFile), to prevent transmitting credentials and
// tenant configs in cleartext.
func (cfg *Config) Validate() error {
	if cfg.URI.URL == nil {
		return nil
	}
	u := cfg.URI.URL
	if u.Scheme == "memory" || u.Scheme == "" {
		return nil
	}
	mode := u.Query().Get("sslmode")
	var hasInlinePassword bool
	if u.User != nil {
		_, hasInlinePassword = u.User.Password()
	}
	if (mode == "disable" || mode == "allow" || mode == "prefer") && (hasInlinePassword || cfg.PasswordFile != "") {
		return errors.New("configs.database.uri must use sslmode=require or stronger when a database password is configured")
	}
	return nil
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

	if cfg.URI.URL == nil {
		return nil, fmt.Errorf("configs.database.uri is required")
	}

	// Copy the parsed URL so we don't mutate the shared config value when
	// injecting the password from PasswordFile.
	parsed := *cfg.URI.URL
	u := &parsed

	if len(cfg.PasswordFile) != 0 {
		if u.User == nil {
			return nil, fmt.Errorf("--database.password-file requires username in --database.uri")
		}
		passwordBytes, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("Could not read database password file: %v", err)
		}
		// Trim whitespace/newlines so a trailing newline in the password
		// file does not become part of the credential sent to Postgres.
		u.User = url.UserPassword(u.User.Username(), strings.TrimSpace(string(passwordBytes)))
	}

	var (
		d   DB
		err error
	)
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
