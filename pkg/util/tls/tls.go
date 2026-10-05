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
	errKeyMissing            = errors.New("certificate given but no key configured")
	errCertMissing           = errors.New("key given but no certificate configured")
	errServerCertMissing     = errors.New("server TLS requires both a certificate and a key (tls_cert_path and tls_key_path)")
	errServerClientCAMissing = errors.New("server TLS requires a client CA (tls_ca_path) in order to authenticate inbound peers; without it any peer can connect")
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

// GetServerTLSConfig initialises a *tls.Config suitable for use by a TLS
// *server* (e.g. a tls.Listen call), reusing the certificate/key and CA
// configured on this ClientConfig.
//
// Unlike GetTLSConfig (which returns a client-side configuration whose only
// authentication is of the *server*), the returned config requires inbound
// peers to present a certificate that chains to the configured CA
// (ClientAuth = RequireAndVerifyClientCert, ClientCAs = CAPath). This is
// used to authenticate peers on protocols where the ClientConfig is reused
// to provision both client and server endpoints — in particular the
// memberlist gossip transport, which previously built its listener via
// GetTLSConfig() and therefore left ClientAuth at the Go default of
// NoClientCert, accepting any inbound peer.
//
// Both a server certificate (CertPath/KeyPath) and a client CA (CAPath)
// are mandatory; without them it is impossible to authenticate incoming
// connections.
func (cfg *ClientConfig) GetServerTLSConfig() (*tls.Config, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errServerCertMissing
	}
	if cfg.CAPath == "" {
		return nil, errServerClientCAMissing
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load server TLS certificate %s,%s", cfg.CertPath, cfg.KeyPath)
	}

	caCert, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading client CA cert: %s", cfg.CAPath)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caCert) {
		return nil, errors.Errorf("failed to parse any client CA certificate from %s", cfg.CAPath)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
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
