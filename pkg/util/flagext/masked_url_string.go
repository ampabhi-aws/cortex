package flagext

import "net/url"

// MaskedURLString is a string-backed value that behaves like a plain string for
// flag parsing but, when marshalled to YAML, redacts the userinfo password of
// any URL it contains. This is intended for configuration fields that are
// documented as URLs (and routinely carry basic-auth credentials in the
// userinfo component) but whose consumers already parse the raw string
// themselves (e.g. url.Parse), so they cannot be changed to flagext.URLValue
// without rewriting those consumers.
//
// The redaction is best-effort: if the value does not parse as a URL, it is
// emitted verbatim. The underlying Value is unchanged so runtime consumers see
// the real credentials.
type MaskedURLString struct {
	Value string
}

// String implements flag.Value.
func (v MaskedURLString) String() string {
	return v.Value
}

// Set implements flag.Value.
func (v *MaskedURLString) Set(s string) error {
	v.Value = s
	return nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *MaskedURLString) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return v.Set(s)
}

// MarshalYAML implements yaml.Marshaler. It parses the string as a URL and, if
// successful, replaces any userinfo password with "********". A value that
// does not parse as a URL is emitted verbatim.
func (v MaskedURLString) MarshalYAML() (interface{}, error) {
	return redactURLUserinfoPassword(v.Value), nil
}

// MaskedURLStringList is like MaskedURLString but accepts a comma-separated
// list of URLs (as used by, e.g., ruler.alertmanager-url) and redacts the
// userinfo password of each entry independently when marshalling to YAML.
type MaskedURLStringList struct {
	Value string
}

// String implements flag.Value.
func (v MaskedURLStringList) String() string {
	return v.Value
}

// Set implements flag.Value.
func (v *MaskedURLStringList) Set(s string) error {
	v.Value = s
	return nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *MaskedURLStringList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return v.Set(s)
}

// MarshalYAML implements yaml.Marshaler. It splits the string on "," and
// redacts the userinfo password of every URL that parses successfully.
func (v MaskedURLStringList) MarshalYAML() (interface{}, error) {
	if v.Value == "" {
		return "", nil
	}
	// Walk the string without allocating a split slice for the common
	// single-URL case.
	start := 0
	out := make([]byte, 0, len(v.Value))
	for i := 0; i <= len(v.Value); i++ {
		if i == len(v.Value) || v.Value[i] == ',' {
			if len(out) > 0 {
				out = append(out, ',')
			}
			out = append(out, redactURLUserinfoPassword(v.Value[start:i])...)
			start = i + 1
		}
	}
	return string(out), nil
}

// redactURLUserinfoPassword returns s with any userinfo password replaced by
// "********". A value that does not parse as a URL is returned verbatim.
func redactURLUserinfoPassword(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	if _, set := u.User.Password(); !set {
		return s
	}
	u.User = url.UserPassword(u.User.Username(), "********")
	return u.String()
}
