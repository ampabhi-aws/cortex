package util

import (
	"net/url"
	"regexp"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

// redactedPlaceholder is used in place of a credential value in a URL
// userinfo component.
const redactedPlaceholder = "xxxxx"

// MaskedPlaceholder is the string substituted in place of a redacted
// credential value, matching the format used by flagext.Secret.MarshalYAML.
const MaskedPlaceholder = "********"

// credentialKeyRegexp matches YAML keys that are considered sensitive and
// should never be emitted in cleartext over /config and /runtime_config.
//
// The pattern is intentionally conservative: it matches whole-word keys such
// as "password", "secret", "token", "credentials" or a key that *ends* with
// "_password" / "_secret" / "_token" / "_credential(s)". It deliberately does
// not match generic suffixes like "_key" or "_id" because many legitimate
// non-secret fields contain those (for example access_key_id, kms_key_id,
// tls_key_path, instance_id).
var credentialKeyRegexp = regexp.MustCompile(`(?i)(^|_)(password|passwd|secret|token|credential|credentials|api_key|apikey|access_key|private_key|signing_key|auth_key|encryption_key|session_key)$`)

// urlLikeKeyRegexp matches YAML keys whose string value may legitimately
// embed a user:password@ component (e.g. configs.database.uri or
// ruler.alertmanager_url). Values of such keys are re-written with
// RedactURLCredentials when emitted.
var urlLikeKeyRegexp = regexp.MustCompile(`(?i)(^|_)(url|uri|dsn|endpoint)$`)

// RedactURLCredentials returns a copy of raw with any userinfo component
// stripped and replaced. Supports comma-separated URL lists.
func RedactURLCredentials(raw string) string {
	if raw == "" {
		return raw
	}
	if strings.Contains(raw, ",") {
		parts := strings.Split(raw, ",")
		for i, p := range parts {
			parts[i] = redactSingleURL(p)
		}
		return strings.Join(parts, ",")
	}
	return redactSingleURL(raw)
}

func redactSingleURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err == nil && u.User != nil {
		u.User = url.UserPassword(redactedPlaceholder, redactedPlaceholder)
		return u.String()
	}
	return raw
}

// RedactYAMLConfig marshals v to YAML, walks the resulting generic tree,
// and replaces values whose keys look like credentials with a mask.
// It is a defence-in-depth pass intended for the /config and /runtime_config
// handlers; type-level masking (flagext.Secret, custom MarshalYAML) remains
// the primary mechanism.
func RedactYAMLConfig(v interface{}) (interface{}, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded interface{}
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	return redactYAMLNode(decoded, ""), nil
}

func redactYAMLNode(node interface{}, parentKey string) interface{} {
	switch n := node.(type) {
	case map[interface{}]interface{}:
		for k, v := range n {
			keyStr, _ := k.(string)
			n[k] = redactYAMLNode(v, keyStr)
		}
		return n
	case map[string]interface{}:
		for k, v := range n {
			n[k] = redactYAMLNode(v, k)
		}
		return n
	case []interface{}:
		for i, v := range n {
			n[i] = redactYAMLNode(v, parentKey)
		}
		return n
	default:
		if parentKey == "" {
			return node
		}
		if credentialKeyRegexp.MatchString(parentKey) {
			if s, ok := node.(string); ok {
				if s == "" {
					return s
				}
				if urlLikeKeyRegexp.MatchString(parentKey) && looksLikeURL(s) {
					return RedactURLCredentials(s)
				}
				return MaskedPlaceholder
			}
			return node
		}
		if urlLikeKeyRegexp.MatchString(parentKey) {
			if s, ok := node.(string); ok {
				return RedactURLCredentials(s)
			}
		}
		return node
	}
}

func looksLikeURL(s string) bool {
	return strings.Contains(s, "://")
}
