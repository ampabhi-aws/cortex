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

// URI is a database URI string whose MarshalYAML implementation strips any
// embedded userinfo (user:password@host) so that credentials inlined into the
// URI are not emitted when the live configuration is serialised (for example
// by the unauthenticated /config endpoint). The in-process value is preserved
// in Value so that database connection setup still has access to the full URI.
type URI struct {
	Value string
}

// String implements flag.Value.
func (u URI) String() string {
	return u.Value
}

// Set implements flag.Value.
func (u *URI) Set(s string) error {
	u.Value = s
	return nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (u *URI) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return u.Set(s)
}

// MarshalYAML implements yaml.Marshaler, stripping userinfo so inline
// credentials are never emitted.
func (u URI) MarshalYAML() (interface{}, error) {
	if u.Value == "" {
		return "", nil
	}
	parsed, err := url.Parse(u.Value)
	if err != nil {
		// If the URI is not parseable, redact it entirely to avoid leaking
		// potentially-sensitive content.
		return "********", nil
	}
	if parsed.User != nil {
		// Replace userinfo with a redacted sentinel preserving the fact that
		// a username was configured.
		parsed.User = url.UserPassword("xxx", "xxx")
	}
	return parsed.String(), nil
}

// Config configures the database.
type Config struct {
	URI           URI    `yaml:"uri"`
	MigrationsDir string `yaml:"migrations_dir"`
	PasswordFile  string `yaml:"password_file"`

	// Allow injection of mock DBs for unit testing.
	Mock DB `yaml:"-"`
}

// RegisterFlags adds the flags required to configure this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	cfg.URI.Value = "postgres://postgres@configs-db.weave.local/configs?sslmode=disable"
	f.Var(&cfg.URI, "configs.database.uri", "URI where the database can be found (for dev you can use memory://)")
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

	u, err := url.Parse(cfg.URI.Value)
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
