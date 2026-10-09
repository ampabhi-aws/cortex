package cortex

import (
	"flag"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// credentialNameRegex matches any struct field whose Go name or yaml tag
// suggests it carries a credential.
var credentialNameRegex = regexp.MustCompile("(?i)(password|secret|token|key)")

// allowedPlaintextFields lists fields that match credentialNameRegex but
// legitimately hold non-sensitive data (file paths, identifiers, algorithm
// names, labels). Keeping this list explicit forces a conscious review when
// a new candidate credential field appears in cortex.Config.
var allowedPlaintextFields = map[string]struct{}{
	// Public key material.
	"PublicKey":    {},
	"public_key":   {},
	"ClientKey":    {},
	"peer_pub_key": {},

	// Paths to secrets, not the secrets themselves.
	"KeyPath":                 {},
	"key_file":                {},
	"keyfile":                 {},
	"password_file":           {},
	"PasswordFile":            {},
	"client_key_file":         {},
	"ClientKeyFile":           {},
	"service_account_file":    {},
	"CredentialsFile":         {},
	"credentials_file":        {},
	"SharedCredentialsFile":   {},
	"shared_credentials_file": {},
	"KeyFile":                 {},
	"TokenFile":               {},
	"token_file":              {},
	"secret_file":             {},
	"SecretFile":              {},

	// Non-credential uses of the key term.
	"KeyPrefix":          {},
	"key_prefix":         {},
	"RoutingKey":         {},
	"routing_key":        {},
	"PartitionKey":       {},
	"partition_key":      {},
	"PrimaryKeyColumn":   {},
	"primary_key_column": {},
	"ShardByAllLabels":   {},
	"Sortkey":            {},
	"RingKey":            {},

	// Labels / tags.
	"KeyLabel":  {},
	"key_label": {},

	// Signing / encryption algorithm names (not keys).
	"SigningKeyAlgorithm":        {},
	"signing_key_algorithm":      {},
	"SSEKMSEncryptionContext":    {},
	"sse_kms_encryption_context": {},

	// S3 SSE KMS key ID is an identifier, not key material.
	"KMSKeyID":          {},
	"kms_key_id":        {},
	"S3SSEKMSKeyID":     {},
	"s3_sse_kms_key_id": {},

	// S3 access key identifier (not the secret part - the paired
	// SecretAccessKey is a flagext.Secret).
	"AccessKeyID":   {},
	"access_key_id": {},

	// Ring token housekeeping fields (counts and file paths).
	"NumTokens":           {},
	"num_tokens":          {},
	"TokensFilePath":      {},
	"tokens_file_path":    {},
	"TokensObservePeriod": {},
	"ShowTokens":          {},

	// Consul watch tuning - the Go field name mentions Key but the field
	// does not hold any credential material.
	"WatchKeyRateLimit": {},
	"WatchKeyBurstSize": {},

	// TLS key file path.
	"tls_key_path":   {},
	"TLSKeyPath":     {},
	"ClientCertPath": {},
	"ServerCertPath": {},
}

func TestConfigCredentialFieldsAreSecrets(t *testing.T) {
	cfg := &Config{}
	cfg.RegisterFlags(flag.NewFlagSet("test", flag.PanicOnError))

	secretType := reflect.TypeOf(flagext.Secret{})

	var violations []string
	seen := map[reflect.Type]struct{}{}
	walkConfig(reflect.TypeOf(*cfg), "", secretType, seen, &violations)

	if len(violations) > 0 {
		t.Fatalf(
			"the following cortex.Config fields look like credentials but are not flagext.Secret; "+
				"convert them to flagext.Secret so DefaultConfigHandler masks them in /config output:\n  - %s",
			strings.Join(violations, "\n  - "),
		)
	}
}

func walkConfig(t reflect.Type, pathPrefix string, secretType reflect.Type, seen map[reflect.Type]struct{}, out *[]string) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	if _, ok := seen[t]; ok {
		return
	}
	// Only walk Cortex-owned types. Vendored third-party structs may legally
	// expose plaintext credential fields that Cortex consumes but does not
	// serialize into the /config dump.
	if pkgPath := t.PkgPath(); pkgPath != "" && !strings.HasPrefix(pkgPath, "github.com/cortexproject/cortex/") {
		return
	}
	seen[t] = struct{}{}
	defer delete(seen, t)

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}

		yamlTag := strings.SplitN(f.Tag.Get("yaml"), ",", 2)[0]
		if yamlTag == "-" {
			continue
		}

		fieldPath := joinPath(pathPrefix, f.Name)

		if looksLikeCredential(f.Name, yamlTag) && f.Type != secretType {
			if _, ok := allowedPlaintextFields[f.Name]; !ok {
				if _, ok := allowedPlaintextFields[yamlTag]; !ok {
					*out = append(*out, formatViolation(fieldPath, yamlTag, f.Type.String()))
				}
			}
		}

		ft := f.Type
		for ft.Kind() == reflect.Ptr || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft != secretType {
			walkConfig(ft, fieldPath, secretType, seen, out)
		}
	}
}

func looksLikeCredential(fieldName, yamlTag string) bool {
	if credentialNameRegex.MatchString(fieldName) {
		return true
	}
	if yamlTag != "" && credentialNameRegex.MatchString(yamlTag) {
		return true
	}
	return false
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func formatViolation(path, yamlTag, typeName string) string {
	if yamlTag == "" {
		return path + " (type " + typeName + ")"
	}
	return path + " (yaml:" + yamlTag + ", type " + typeName + ")"
}
