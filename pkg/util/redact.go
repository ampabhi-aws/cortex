package util

import (
	"net/url"
	"strings"
)

// redactedMarker matches the mask used by flagext.Secret so that /config
// output is consistent across all redaction mechanisms.
const redactedMarker = "********"

// yamlSecretKeys is the set of top-level map keys whose string value is treated
// as a credential and replaced with redactedMarker when it is non-empty. This
// catches credential fields that are stored as plain string (not flagext.Secret)
// and therefore are not masked by the yaml.Marshaler on that type. Keep this
// list in sync with any new plain-string credential fields that may be
// serialized by /config.
var yamlSecretKeys = map[string]bool{
	// Historically plain-string credential fields in the Cortex configuration.
	// flagext.Secret-typed fields already render as "********" so they are not
	// listed here.
	"basic_auth_password": true,
	// Catch-alls for any backend added later that happens to use these keys.
	"password":     true,
	"client_secret": true,
	"api_key":       true,
}

// yamlURIKeys is the set of map keys whose string value may be a URL/DSN that
// embeds user credentials (e.g. the configs database Postgres DSN). The
// userinfo of each such value is redacted while the rest of the URL is
// preserved for operator visibility.
var yamlURIKeys = map[string]bool{
	"uri": true,
	"url": true,
	// alertmanager / notifier URLs may embed basic-auth credentials.
	"alertmanager_url": true,
}

// RedactSecretsInYAMLMap walks a YAML-decoded value (as produced by
// YAMLMarshalUnmarshal) and redacts any credential-looking string in place.
// The walk follows nested map[interface{}]interface{} and []interface{}
// containers, which is the shape yaml.v2 produces for arbitrary objects.
//
// This is a defense-in-depth pass used by /config so that credentials cannot
// leak via plain-string fields that are not typed as flagext.Secret, and so
// that URI DSNs with inline passwords (e.g. configs.database.uri=postgres://
// user:pw@host/db) have their userinfo stripped before the YAML is written to
// the response.
func RedactSecretsInYAMLMap(v interface{}) {
	switch m := v.(type) {
	case map[interface{}]interface{}:
		for k, val := range m {
			keyStr, _ := k.(string)
			lowerKey := strings.ToLower(keyStr)
			switch sv := val.(type) {
			case string:
				if sv == "" {
					continue
				}
				if yamlSecretKeys[lowerKey] {
					m[k] = redactedMarker
					continue
				}
				if yamlURIKeys[lowerKey] {
					m[k] = redactUserinfo(sv)
				}
			case map[interface{}]interface{}, []interface{}:
				RedactSecretsInYAMLMap(sv)
			}
		}
	case []interface{}:
		for _, val := range m {
			switch val.(type) {
			case map[interface{}]interface{}, []interface{}:
				RedactSecretsInYAMLMap(val)
			}
		}
	}
}

// redactUserinfo returns the input string with the userinfo (user:password@)
// section of any URL replaced by "user:********@". If the input is not a URL
// or has no userinfo, it is returned unchanged.
func redactUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.User == nil {
		return raw
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		// No embedded password; nothing sensitive to redact.
		return raw
	}
	user := u.User.Username()
	u.User = url.User(user)
	redacted := u.String()
	// Re-insert the mask after the username so operators can still see the
	// scheme/host/path for debugging but the credential is removed.
	if user == "" {
		return strings.Replace(redacted, "://", "://"+redactedMarker+"@", 1)
	}
	return strings.Replace(redacted, "://"+user+"@", "://"+user+":"+redactedMarker+"@", 1)
}
