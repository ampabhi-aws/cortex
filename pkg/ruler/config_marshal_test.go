package ruler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TestConfig_MarshalYAML_MasksAlertmanagerURLPassword asserts that any
// password embedded in the userinfo of ruler.alertmanager_url (a
// comma-separated list of URLs) is masked when the config is YAML-marshalled.
// This is what the unauthenticated GET /config endpoint returns, so leaking
// the plaintext basic-auth credential there is a disclosure of the
// Alertmanager notification credential.
func TestConfig_MarshalYAML_MasksAlertmanagerURLPassword(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:           "empty is preserved",
			url:            "",
			mustContain:    nil,
			mustNotContain: []string{"********"},
		},
		{
			name:           "no credentials is preserved verbatim",
			url:            "http://alertmanager.default.svc.cluster.local/alertmanager",
			mustContain:    []string{"http://alertmanager.default.svc.cluster.local/alertmanager"},
			mustNotContain: []string{"********", ":@"},
		},
		{
			name:           "username only is preserved",
			url:            "http://marco@alertmanager.default.svc.cluster.local/alertmanager",
			mustContain:    []string{"marco@alertmanager.default.svc.cluster.local"},
			mustNotContain: []string{"********", "hunter2"},
		},
		{
			name:           "password in single URL is masked",
			url:            "http://marco:hunter2@alertmanager-0.default.svc.cluster.local/alertmanager",
			mustContain:    []string{"marco:********@alertmanager-0.default.svc.cluster.local"},
			mustNotContain: []string{"hunter2", ":hunter2@"},
		},
		{
			name:           "password in comma-separated list is masked for every entry",
			url:            "http://marco:hunter2@am-0/alertmanager,https://neo:trinity@am-1/alertmanager,http://am-2/alertmanager",
			mustContain:    []string{"marco:********@am-0", "neo:********@am-1", "http://am-2/alertmanager"},
			mustNotContain: []string{"hunter2", "trinity"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{AlertmanagerURL: tc.url}
			out, err := yaml.Marshal(cfg)
			require.NoError(t, err)
			rendered := string(out)
			for _, s := range tc.mustContain {
				require.Contains(t, rendered, s, "rendered YAML:\n%s", rendered)
			}
			for _, s := range tc.mustNotContain {
				require.NotContains(t, rendered, s, "rendered YAML:\n%s", rendered)
			}
			// Sanity: there is no stray ":<password>@" userinfo left anywhere.
			require.False(t, strings.Contains(rendered, "hunter2"), "password leaked: %s", rendered)
		})
	}
}
