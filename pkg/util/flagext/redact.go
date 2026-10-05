package flagext

import (
	"net/url"
	"strings"
)

// RedactedURLValue is the string used to replace a password embedded in
// a URL's userinfo component when marshalling a value that may contain a
// credential inside a composite URL/DSN string.
const RedactedURLValue = "xxxxx"

// RedactSecretInURL parses raw as a URL and, if its userinfo component
// contains a password, replaces that password with RedactedURLValue. If
// raw cannot be parsed as a URL or does not contain a password, the
// original string is returned unchanged.
//
// This is intended for use when a configuration field carries a
// credential embedded inside a larger URL/DSN string (for example a
// Postgres DSN or a Prometheus Alertmanager URL), where the field-level
// Secret type cannot be used because only part of the string is
// sensitive.
func RedactSecretInURL(raw string) string {
	if raw == "" {
		return raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		// We cannot parse the value. To avoid leaking a password that
		// might still be present inside an unparseable string, replace
		// the entire value with the redaction marker rather than
		// returning it verbatim.
		return RedactedURLValue
	}

	if u.User == nil {
		return raw
	}

	if _, hasPassword := u.User.Password(); !hasPassword {
		return raw
	}

	u.User = url.UserPassword(u.User.Username(), RedactedURLValue)
	return u.String()
}

// RedactSecretInURLList applies RedactSecretInURL to every entry in a
// separator-delimited list of URLs (for example the comma-separated
// Alertmanager URL list consumed by the ruler). The original separator
// characters and empty entries are preserved.
func RedactSecretInURLList(raw, sep string) string {
	if raw == "" || sep == "" {
		return RedactSecretInURL(raw)
	}

	parts := strings.Split(raw, sep)
	for i, p := range parts {
		parts[i] = RedactSecretInURL(p)
	}
	return strings.Join(parts, sep)
}
