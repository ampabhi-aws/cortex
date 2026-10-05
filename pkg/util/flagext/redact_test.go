package flagext

import "testing"

func TestRedactSecretInURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"empty", "", ""},
		{"no_user", "https://alertmanager.example.com/", "https://alertmanager.example.com/"},
		{"user_only", "https://alice@alertmanager.example.com/", "https://alice@alertmanager.example.com/"},
		{"user_and_password", "https://alice:hunter2@alertmanager.example.com/", "https://alice:" + RedactedURLValue + "@alertmanager.example.com/"},
		{"postgres_dsn", "postgres://user:password@configs-db/configs?sslmode=disable", "postgres://user:" + RedactedURLValue + "@configs-db/configs?sslmode=disable"},
		{"empty_password", "postgres://user:@configs-db/configs", "postgres://user:" + RedactedURLValue + "@configs-db/configs"},
		{"plain_string", "notaurl", "notaurl"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecretInURL(tc.in)
			if got != tc.out {
				t.Fatalf("RedactSecretInURL(%q) = %q, want %q", tc.in, got, tc.out)
			}
		})
	}
}

func TestRedactSecretInURLList(t *testing.T) {
	in := "https://alice:hunter2@a.example.com/,https://b.example.com/,https://carol:topsecret@c.example.com/"
	out := "https://alice:" + RedactedURLValue + "@a.example.com/,https://b.example.com/,https://carol:" + RedactedURLValue + "@c.example.com/"
	if got := RedactSecretInURLList(in, ","); got != out {
		t.Fatalf("RedactSecretInURLList: got %q, want %q", got, out)
	}

	if got := RedactSecretInURLList("", ","); got != "" {
		t.Fatalf("empty list: got %q", got)
	}
}
