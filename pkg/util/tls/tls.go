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

// GetServerTLSConfig initialises a server-side tls.Config from config options.
//
// Unlike GetTLSConfig, which produces a client-side configuration, this method
// returns a *tls.Config suitable for use with tls.Listen / tls.NewListener. The
// server certificate is loaded from cfg.CertPath/cfg.KeyPath. When clientCAPath
// is non-empty, the configured CA bundle is installed as ClientCAs and
// ClientAuth is set to tls.RequireAndVerifyClientCert so that inbound peers
// must present a certificate chained to that CA. When clientCAPath is empty,
// clientAuth controls the ClientAuth policy (default tls.NoClientCert).
func (cfg *ClientConfig) GetServerTLSConfig(clientCAPath string, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("server certificate and key must both be configured for TLS listener")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load server TLS certificate %s,%s", cfg.CertPath, cfg.KeyPath)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
	}

	if clientCAPath != "" {
		caCert, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, errors.Wrapf(err, "error loading client CA cert: %s", clientCAPath)
		}
		clientCAPool := x509.NewCertPool()
		if !clientCAPool.AppendCertsFromPEM(caCert) {
			return nil, errors.Errorf("failed to parse any client CA certificates from %s", clientCAPath)
		}
		config.ClientCAs = clientCAPool
		// Enforce mutual TLS when a client CA is supplied.
		if config.ClientAuth < tls.RequireAndVerifyClientCert {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
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
