package filesystem

import (
	"errors"
	"flag"
)

// ErrEmptyDirectory is returned when the filesystem storage directory is empty.
var ErrEmptyDirectory = errors.New("missing directory for filesystem bucket")

// Config stores the configuration for storing and accessing objects in the local filesystem.
type Config struct {
	Directory string `yaml:"dir"`
}

// RegisterFlags registers the flags for filesystem storage
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	cfg.RegisterFlagsWithPrefix("", f)
}

// RegisterFlagsWithPrefix registers the flags for filesystem storage with the provided prefix
func (cfg *Config) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.Directory, prefix+"filesystem.dir", "", "Local filesystem storage directory.")
}

// Validate the config.
func (cfg *Config) Validate() error {
	if cfg.Directory == "" {
		return ErrEmptyDirectory
	}
	return nil
}
