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

// GetServerTLSConfig initialises a server-side tls.Config from the same
// options as GetTLSConfig, but applied to the serving side of a listener.
//
// Unlike GetTLSConfig, this intentionally ignores InsecureSkipVerify and
// ServerName (which are only meaningful for a TLS client) and instead
// configures ClientAuth: tls.RequireAndVerifyClientCert together with
// ClientCAs populated from CAPath, so an incoming peer MUST present a
// certificate signed by the configured CA. The server certificate and key
// come from CertPath/KeyPath. A CA path is required to validate peer
// certificates: without one no peer could ever be verified.
func (cfg *ClientConfig) GetServerTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	if cfg.CAPath == "" {
		return nil, errors.New("a CA certificate path (tls_ca_path) is required to authenticate peers on the server-side TLS listener")
	}

	caCert, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading ca cert: %s", cfg.CAPath)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.Errorf("failed to append any CA certificate from %s", cfg.CAPath)
	}
	config.ClientCAs = caCertPool

	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("both a server certificate (tls_cert_path) and key (tls_key_path) are required for the server-side TLS listener")
	}
	serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load TLS certificate %s,%s", cfg.CertPath, cfg.KeyPath)
	}
	config.Certificates = []tls.Certificate{serverCert}

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
