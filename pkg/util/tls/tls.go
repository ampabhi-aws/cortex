package tls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Named tls.ClientAuthType values exposed via configuration. Empty string
// maps to NoClientCert (the Go default), matching previous behaviour.
const (
	ClientAuthNone             = "NoClientCert"
	ClientAuthRequest          = "RequestClientCert"
	ClientAuthRequireAnyCert   = "RequireAnyClientCert"
	ClientAuthVerifyIfGiven    = "VerifyClientCertIfGiven"
	ClientAuthRequireAndVerify = "RequireAndVerifyClientCert"
)

// ParseClientAuthType maps a string into a tls.ClientAuthType. An empty
// string selects tls.NoClientCert.
func ParseClientAuthType(s string) (tls.ClientAuthType, error) {
	switch s {
	case "", ClientAuthNone:
		return tls.NoClientCert, nil
	case ClientAuthRequest:
		return tls.RequestClientCert, nil
	case ClientAuthRequireAnyCert:
		return tls.RequireAnyClientCert, nil
	case ClientAuthVerifyIfGiven:
		return tls.VerifyClientCertIfGiven, nil
	case ClientAuthRequireAndVerify:
		return tls.RequireAndVerifyClientCert, nil
	default:
		return tls.NoClientCert, fmt.Errorf("unknown TLS client auth type: %q", s)
	}
}

// ServerConfig is the config for a server-side TLS listener. Unlike
// ClientConfig it exposes ClientAuth and the client-CA pool, so callers can
// require and verify a client certificate (mutual TLS) rather than silently
// accepting any peer.
type ServerConfig struct {
	CertPath     string `yaml:"tls_cert_path"`
	KeyPath      string `yaml:"tls_key_path"`
	ClientCAPath string `yaml:"tls_client_ca_path"`
	// ClientAuth is one of NoClientCert, RequestClientCert,
	// RequireAnyClientCert, VerifyClientCertIfGiven,
	// RequireAndVerifyClientCert. Empty = NoClientCert.
	ClientAuth string `yaml:"tls_client_auth"`
}

// RegisterFlagsWithPrefix registers server-side TLS flags with prefix.
func (cfg *ServerConfig) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.CertPath, prefix+".tls-cert-path", "", "Path to the server certificate presented to peers.")
	f.StringVar(&cfg.KeyPath, prefix+".tls-key-path", "", "Path to the private key for the server certificate.")
	f.StringVar(&cfg.ClientCAPath, prefix+".tls-client-ca-path", "", "Path to the CA certificates file used to verify client certificates presented by peers.")
	f.StringVar(&cfg.ClientAuth, prefix+".tls-client-auth", "", "Policy for TLS client authentication. One of NoClientCert, RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven, RequireAndVerifyClientCert. Defaults to NoClientCert, which does not authenticate peers.")
}

// GetTLSConfig initialises a *tls.Config suitable for use with tls.Listen /
// tls.NewListener. It sets ClientAuth and ClientCAs based on the
// configuration, so when ClientAuth is RequireAndVerifyClientCert the
// listener actually verifies peer certificates against the configured CA.
func (cfg *ServerConfig) GetTLSConfig() (*tls.Config, error) {
	clientAuth, err := ParseClientAuthType(cfg.ClientAuth)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		ClientAuth: clientAuth,
	}

	if cfg.CertPath != "" || cfg.KeyPath != "" {
		if cfg.CertPath == "" {
			return nil, errCertMissing
		}
		if cfg.KeyPath == "" {
			return nil, errKeyMissing
		}
		serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load TLS server certificate %s,%s", cfg.CertPath, cfg.KeyPath)
		}
		config.Certificates = []tls.Certificate{serverCert}
	}

	if cfg.ClientCAPath != "" {
		caCert, err := os.ReadFile(cfg.ClientCAPath)
		if err != nil {
			return nil, errors.Wrapf(err, "error loading client ca cert: %s", cfg.ClientCAPath)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client ca cert: %s", cfg.ClientCAPath)
		}
		config.ClientCAs = pool
	} else if clientAuth == tls.VerifyClientCertIfGiven || clientAuth == tls.RequireAndVerifyClientCert {
		return nil, fmt.Errorf("tls-client-auth %q requires tls-client-ca-path to be set", cfg.ClientAuth)
	}

	return config, nil
}

// ClientConfig is the config for client TLS.
type ClientConfig struct {
	CertPath           string `yaml:"tls_cert_path"`
	KeyPath            string `yaml:"tls_key_path"`
	CAPath             string `yaml:"tls_ca_path"`
	ServerName         string `yaml:"tls_server_name"`
	InsecureSkipVerify bool   `yaml:"tls_insecure_skip_verify"`
}

var (
	errKeyMissing  = errors.New("certificate given but no key configured")
	errCertMissing = errors.New("key given but no certificate configured")
)

// RegisterFlagsWithPrefix registers flags with prefix.
func (cfg *ClientConfig) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.CertPath, prefix+".tls-cert-path", "", "Path to the client certificate file, which will be used for authenticating with the server. Also requires the key path to be configured.")
	f.StringVar(&cfg.KeyPath, prefix+".tls-key-path", "", "Path to the key file for the client certificate. Also requires the client certificate to be configured.")
	f.StringVar(&cfg.CAPath, prefix+".tls-ca-path", "", "Path to the CA certificates file to validate server certificate against. If not set, the host's root CA certificates are used.")
	f.StringVar(&cfg.ServerName, prefix+".tls-server-name", "", "Override the expected name on the server certificate.")
	f.BoolVar(&cfg.InsecureSkipVerify, prefix+".tls-insecure-skip-verify", false, "Skip validating server certificate.")
}

// GetTLSConfig initialises tls.Config from config options
func (cfg *ClientConfig) GetTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.ServerName,
	}

	// read ca certificates
	if cfg.CAPath != "" {
		var caCertPool *x509.CertPool
		caCert, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, errors.Wrapf(err, "error loading ca cert: %s", cfg.CAPath)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		config.RootCAs = caCertPool
	}

	// read client certificate
	if cfg.CertPath != "" || cfg.KeyPath != "" {
		if cfg.CertPath == "" {
			return nil, errCertMissing
		}
		if cfg.KeyPath == "" {
			return nil, errKeyMissing
		}
		clientCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load TLS certificate %s,%s", cfg.CertPath, cfg.KeyPath)
		}
		config.Certificates = []tls.Certificate{clientCert}
	}

	return config, nil
}

// GetGRPCDialOptions creates GRPC DialOptions for TLS
func (cfg *ClientConfig) GetGRPCDialOptions(enabled bool) ([]grpc.DialOption, error) {
	if !enabled {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}

	tlsConfig, err := cfg.GetTLSConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error creating grpc dial options")
	}

	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}
