package flagext

import (
	"net/url"
	"strings"
)

// URLString is a string that holds one or more comma-separated URLs. It
// behaves like a regular string, but its MarshalYAML implementation
// redacts the userinfo portion of each URL so credentials embedded in
// the DSN are not leaked by callers that serialize the whole
// configuration (for example the Cortex /config endpoint).
type URLString string

// String implements flag.Value.
func (v URLString) String() string {
	return string(v)
}

// Set implements flag.Value.
func (v *URLString) Set(s string) error {
	*v = URLString(s)
	return nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *URLString) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*v = URLString(s)
	return nil
}

// MarshalYAML implements yaml.Marshaler. Any URL in the comma-separated
// value that embeds a password in its userinfo is redacted to the form
// user:********@host. Non-URL values (and URLs without a password) are
// returned unchanged.
func (v URLString) MarshalYAML() (interface{}, error) {
	raw := string(v)
	if raw == "" {
		return "", nil
	}

	parts := strings.Split(raw, ",")
	for i, p := range parts {
		u, err := url.Parse(p)
		if err != nil || u.User == nil {
			continue
		}
		if _, set := u.User.Password(); set {
			u.User = url.UserPassword(u.User.Username(), "********")
			parts[i] = u.String()
		}
	}
	return strings.Join(parts, ","), nil
}
