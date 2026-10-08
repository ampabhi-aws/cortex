package tls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"os"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

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
		caCertPool, err := cfg.loadCAPool()
		if err != nil {
			return nil, err
		}
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

// loadCAPool loads the configured CA certificates into an x509.CertPool. It
// returns an error when the CA file cannot be read; callers should only invoke
// it when a CA path is configured.
func (cfg *ClientConfig) loadCAPool() (*x509.CertPool, error) {
	caCert, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading ca cert: %s", cfg.CAPath)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return pool, nil
}

// GetServerTLSConfig returns a *tls.Config suitable for use on a TLS listener
// that must authenticate its peers (mutual TLS). Unlike GetTLSConfig (which
// produces a client config), this method configures ClientAuth =
// RequireAndVerifyClientCert and the ClientCAs pool so the server requests and
// verifies a client certificate signed by the configured CA. A minimum TLS
// version of 1.2 is enforced.
//
// A CA path and a server certificate/key are required: without a CA the server
// cannot authenticate peers.
func (cfg *ClientConfig) GetServerTLSConfig() (*tls.Config, error) {
	if cfg.CAPath == "" {
		return nil, errors.New("TLS server config requires a CA certificate (tls_ca_path) to authenticate peers")
	}
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("TLS server config requires both a certificate (tls_cert_path) and key (tls_key_path)")
	}

	caCertPool, err := cfg.loadCAPool()
	if err != nil {
		return nil, err
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load TLS certificate %s,%s", cfg.CertPath, cfg.KeyPath)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
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
