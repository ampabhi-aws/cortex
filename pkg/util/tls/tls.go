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
//
// The same struct is also used to configure the server side of a
// mutually-authenticated TLS listener via GetServerTLSConfig(). In that mode
// the ClientCAPath field is used to load the CA bundle that signs peer client
// certificates, and the listener is built with ClientAuth =
// RequireAndVerifyClientCert. See GetServerTLSConfig below.
type ClientConfig struct {
	CertPath           string `yaml:"tls_cert_path"`
	KeyPath            string `yaml:"tls_key_path"`
	CAPath             string `yaml:"tls_ca_path"`
	ServerName         string `yaml:"tls_server_name"`
	InsecureSkipVerify bool   `yaml:"tls_insecure_skip_verify"`
	// ClientCAPath is the CA bundle used by a TLS listener built from this
	// config (see GetServerTLSConfig) to verify peer client certificates. It
	// is only consulted on the server side; dial-time trust still comes from
	// CAPath above.
	ClientCAPath string `yaml:"tls_client_ca_path"`
}

// defaultCipherSuites is an explicit list of modern, forward-secret cipher
// suites used on both the client and server side when building a tls.Config
// from this package. It avoids CBC-SHA / RSA-key-exchange suites that Go's
// TLS stack would otherwise accept by default for TLS 1.2.
var defaultCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
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
	f.StringVar(&cfg.ClientCAPath, prefix+".tls-client-ca-path", "", "Path to the CA certificates file used to verify peer client certificates when this config is used to build a TLS listener (mutual TLS). If empty, the value of tls-ca-path is used.")
}

// GetTLSConfig initialises tls.Config from config options for use by a TLS
// client. The returned config pins MinVersion to TLS 1.2 and uses an explicit
// modern CipherSuites list.
func (cfg *ClientConfig) GetTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ServerName:         cfg.ServerName,
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       defaultCipherSuites,
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

// GetServerTLSConfig initialises a *tls.Config suitable for use as the server
// side of a TLS listener (for example, memberlist gossip over TLS).
//
// Compared to GetTLSConfig it:
//   - requires and verifies a peer client certificate
//     (ClientAuth = RequireAndVerifyClientCert),
//   - loads the client CA bundle from ClientCAPath (falling back to CAPath
//     when ClientCAPath is empty) into ClientCAs,
//   - pins MinVersion to TLS 1.2, and
//   - uses an explicit modern CipherSuites list.
//
// It does not set InsecureSkipVerify or ServerName, which are client-side
// concepts.
func (cfg *ClientConfig) GetServerTLSConfig() (*tls.Config, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("server TLS requires both a certificate and a key")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load TLS certificate %s,%s", cfg.CertPath, cfg.KeyPath)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: defaultCipherSuites,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	clientCAPath := cfg.ClientCAPath
	if clientCAPath == "" {
		clientCAPath = cfg.CAPath
	}
	if clientCAPath == "" {
		return nil, errors.New("server TLS requires a CA bundle (set tls-client-ca-path or tls-ca-path) to verify peer client certificates")
	}

	caCert, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading client ca cert: %s", clientCAPath)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caCert) {
		return nil, errors.Errorf("failed to parse any client CA certificate from %s", clientCAPath)
	}
	config.ClientCAs = clientCAs

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
