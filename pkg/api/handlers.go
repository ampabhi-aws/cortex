package api

import (
	"context"
	"html/template"
	"net/http"
	"path"
	"sync"

	"github.com/go-kit/log"
	"github.com/gorilla/mux"
	"github.com/grafana/regexp"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/route"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	v1 "github.com/prometheus/prometheus/web/api/v1"
	"github.com/weaveworks/common/instrument"
	"github.com/weaveworks/common/middleware"
	yaml "gopkg.in/yaml.v2"

	"github.com/cortexproject/cortex/pkg/purger"
	"github.com/cortexproject/cortex/pkg/querier"
	"github.com/cortexproject/cortex/pkg/querier/stats"
	"github.com/cortexproject/cortex/pkg/util"
)

const (
	SectionAdminEndpoints = "Admin Endpoints:"
	SectionDangerous      = "Dangerous:"
)

func newIndexPageContent() *IndexPageContent {
	return &IndexPageContent{
		content: map[string]map[string]string{},
	}
}

// IndexPageContent is a map of sections to path -> description.
type IndexPageContent struct {
	mu      sync.Mutex
	content map[string]map[string]string
}

func (pc *IndexPageContent) AddLink(section, path, description string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	sectionMap := pc.content[section]
	if sectionMap == nil {
		sectionMap = make(map[string]string)
		pc.content[section] = sectionMap
	}

	sectionMap[path] = description
}

func (pc *IndexPageContent) GetContent() map[string]map[string]string {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	result := map[string]map[string]string{}
	for k, v := range pc.content {
		sm := map[string]string{}
		for smK, smV := range v {
			sm[smK] = smV
		}
		result[k] = sm
	}
	return result
}

var indexPageTemplate = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Cortex</title>
	</head>
	<body>
		<h1>Cortex</h1>
		{{ range $s, $links := . }}
		<p>{{ $s }}</p>
		<ul>
			{{ range $path, $desc := $links }}
				<li><a href="{{ AddPathPrefix $path }}">{{ $desc }}</a></li>
			{{ end }}
		</ul>
		{{ end }}
	</body>
</html>`

func indexHandler(httpPathPrefix string, content *IndexPageContent) http.HandlerFunc {
	templ := template.New("main")
	templ.Funcs(map[string]interface{}{
		"AddPathPrefix": func(link string) string {
			return path.Join(httpPathPrefix, link)
		},
	})
	template.Must(templ.Parse(indexPageTemplate))

	return func(w http.ResponseWriter, r *http.Request) {
		err := templ.Execute(w, content.GetContent())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (cfg *Config) configHandler(actualCfg interface{}, defaultCfg interface{}) http.HandlerFunc {
	if cfg.CustomConfigHandler != nil {
		return cfg.CustomConfigHandler(actualCfg, defaultCfg)
	}
	return DefaultConfigHandler(actualCfg, defaultCfg)
}

// configSensitiveYAMLKeys lists YAML field names whose values must be
// redacted before the config is served over HTTP. The underlying Go types
// for these fields are plain strings (not flagext.Secret) so the type-driven
// masking in pkg/util/flagext.Secret does not cover them; without this
// allowlist they would be returned verbatim by GET /config, leaking
// credentials (Swift/etcd/basic-auth passwords, S3 access key id, configs
// database DSN which commonly embeds a password).
var configSensitiveYAMLKeys = map[string]struct{}{
	"password":            {}, // swift.password, etcd.password, and any other plain-string password field.
	"basic_auth_password": {}, // ruler alertmanager_client basic auth (pkg/util.BasicAuth, inlined into NotifierConfig).
	"access_key_id":       {}, // S3 access key id (its secret counterpart is already flagext.Secret).
	"uri":                 {}, // configs.database.uri — DSN that may embed an inline password.
}

// redactSensitiveConfig walks a yaml-decoded value and replaces any value
// whose yaml key is in configSensitiveYAMLKeys with a mask, when the value
// is a non-empty scalar. Empty scalars are preserved so the output still
// reflects whether the field was configured. The function mutates maps
// in place and returns the (possibly rewritten) value for use with slices.
func redactSensitiveConfig(v interface{}) interface{} {
	switch node := v.(type) {
	case yaml.MapSlice:
		for i, item := range node {
			if ks, ok := item.Key.(string); ok {
				if _, sensitive := configSensitiveYAMLKeys[ks]; sensitive {
					if s, isStr := item.Value.(string); isStr {
						if s == "" {
							node[i].Value = ""
						} else {
							node[i].Value = "********"
						}
						continue
					}
				}
			}
			node[i].Value = redactSensitiveConfig(item.Value)
		}
		return node
	case map[interface{}]interface{}:
		for k, val := range node {
			if ks, ok := k.(string); ok {
				if _, sensitive := configSensitiveYAMLKeys[ks]; sensitive {
					if s, isStr := val.(string); isStr {
						if s == "" {
							node[k] = ""
						} else {
							node[k] = "********"
						}
						continue
					}
				}
			}
			node[k] = redactSensitiveConfig(val)
		}
		return node
	case map[string]interface{}:
		for k, val := range node {
			if _, sensitive := configSensitiveYAMLKeys[k]; sensitive {
				if s, isStr := val.(string); isStr {
					if s == "" {
						node[k] = ""
					} else {
						node[k] = "********"
					}
					continue
				}
			}
			node[k] = redactSensitiveConfig(val)
		}
		return node
	case []interface{}:
		for i, val := range node {
			node[i] = redactSensitiveConfig(val)
		}
		return node
	default:
		return v
	}
}

// sanitizeConfigForResponse marshals cfg to YAML, redacts sensitive fields
// identified by yaml key, and returns a value suitable for re-marshaling as
// the HTTP response. A yaml.MapSlice is used as the intermediate
// representation so that the field order emitted by the Go config structs
// is preserved in the response. This complements the type-driven masking
// performed by flagext.Secret (pkg/util/flagext/secret.go) for the
// credential fields that are still plain strings in the config structs.
func sanitizeConfigForResponse(cfg interface{}) (interface{}, error) {
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var obj yaml.MapSlice
	if err := yaml.Unmarshal(yamlBytes, &obj); err != nil {
		return nil, err
	}
	return redactSensitiveConfig(obj), nil
}

func DefaultConfigHandler(actualCfg interface{}, defaultCfg interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var output interface{}
		switch r.URL.Query().Get("mode") {
		case "diff":
			defaultCfgObj, err := util.YAMLMarshalUnmarshal(defaultCfg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			redactSensitiveConfig(defaultCfgObj)

			actualCfgObj, err := util.YAMLMarshalUnmarshal(actualCfg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			redactSensitiveConfig(actualCfgObj)

			diff, err := util.DiffConfig(defaultCfgObj, actualCfgObj)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			output = diff

		case "defaults":
			sanitized, err := sanitizeConfigForResponse(defaultCfg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			output = sanitized
		default:
			sanitized, err := sanitizeConfigForResponse(actualCfg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			output = sanitized
		}

		util.WriteYAMLResponse(w, output)
	}
}

// NewQuerierHandler returns a HTTP handler that can be used by the querier service to
// either register with the frontend worker query processor or with the external HTTP
// server to fulfill the Prometheus query API.
func NewQuerierHandler(
	cfg Config,
	queryable storage.SampleAndChunkQueryable,
	exemplarQueryable storage.ExemplarQueryable,
	engine *promql.Engine,
	distributor Distributor,
	tombstonesLoader purger.TombstonesLoader,
	reg prometheus.Registerer,
	logger log.Logger,
) http.Handler {
	// Prometheus histograms for requests to the querier.
	querierRequestDuration := promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cortex",
		Name:      "querier_request_duration_seconds",
		Help:      "Time (in seconds) spent serving HTTP requests to the querier.",
		Buckets:   instrument.DefBuckets,
	}, []string{"method", "route", "status_code", "ws"})

	receivedMessageSize := promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cortex",
		Name:      "querier_request_message_bytes",
		Help:      "Size (in bytes) of messages received in the request to the querier.",
		Buckets:   middleware.BodySizeBuckets,
	}, []string{"method", "route"})

	sentMessageSize := promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cortex",
		Name:      "querier_response_message_bytes",
		Help:      "Size (in bytes) of messages sent in response by the querier.",
		Buckets:   middleware.BodySizeBuckets,
	}, []string{"method", "route"})

	inflightRequests := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "cortex",
		Name:      "querier_inflight_requests",
		Help:      "Current number of inflight requests to the querier.",
	}, []string{"method", "route"})

	api := v1.NewAPI(
		engine,
		querier.NewErrorTranslateSampleAndChunkQueryable(queryable), // Translate errors to errors expected by API.
		nil, // No remote write support.
		exemplarQueryable,
		func(context.Context) v1.TargetRetriever { return &querier.DummyTargetRetriever{} },
		func(context.Context) v1.AlertmanagerRetriever { return &querier.DummyAlertmanagerRetriever{} },
		func() config.Config { return config.Config{} },
		map[string]string{}, // TODO: include configuration flags
		v1.GlobalURLOptions{},
		func(f http.HandlerFunc) http.HandlerFunc { return f },
		nil,   // Only needed for admin APIs.
		"",    // This is for snapshots, which is disabled when admin APIs are disabled. Hence empty.
		false, // Disable admin APIs.
		logger,
		func(context.Context) v1.RulesRetriever { return &querier.DummyRulesRetriever{} },
		0, 0, 0, // Remote read samples and concurrency limit.
		false,
		regexp.MustCompile(".*"),
		func() (v1.RuntimeInfo, error) { return v1.RuntimeInfo{}, errors.New("not implemented") },
		&v1.PrometheusVersion{},
		// This is used for the stats API which we should not support. Or find other ways to.
		prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) { return nil, nil }),
		reg,
		nil,
	)

	router := mux.NewRouter()

	// Use a separate metric for the querier in order to differentiate requests from the query-frontend when
	// running Cortex as a single binary.
	inst := middleware.Instrument{
		RouteMatcher:     router,
		Duration:         querierRequestDuration,
		RequestBodySize:  receivedMessageSize,
		ResponseBodySize: sentMessageSize,
		InflightRequests: inflightRequests,
	}
	cacheGenHeaderMiddleware := getHTTPCacheGenNumberHeaderSetterMiddleware(tombstonesLoader)
	middlewares := middleware.Merge(inst, cacheGenHeaderMiddleware)
	router.Use(middlewares.Wrap)

	// Define the prefixes for all routes
	prefix := path.Join(cfg.ServerPrefix, cfg.PrometheusHTTPPrefix)
	legacyPrefix := path.Join(cfg.ServerPrefix, cfg.LegacyHTTPPrefix)

	promRouter := route.New().WithPrefix(path.Join(prefix, "/api/v1"))
	api.Register(promRouter)

	legacyPromRouter := route.New().WithPrefix(path.Join(legacyPrefix, "/api/v1"))
	api.Register(legacyPromRouter)

	// TODO(gotjosh): This custom handler is temporary until we're able to vendor the changes in:
	// https://github.com/prometheus/prometheus/pull/7125/files
	router.Path(path.Join(prefix, "/api/v1/metadata")).Handler(querier.MetadataHandler(distributor))
	router.Path(path.Join(prefix, "/api/v1/read")).Handler(querier.RemoteReadHandler(queryable, logger))
	router.Path(path.Join(prefix, "/api/v1/read")).Methods("POST").Handler(promRouter)
	router.Path(path.Join(prefix, "/api/v1/query")).Methods("GET", "POST").Handler(promRouter)
	router.Path(path.Join(prefix, "/api/v1/query_range")).Methods("GET", "POST").Handler(promRouter)
	router.Path(path.Join(prefix, "/api/v1/query_exemplars")).Methods("GET", "POST").Handler(promRouter)
	router.Path(path.Join(prefix, "/api/v1/labels")).Methods("GET", "POST").Handler(promRouter)
	router.Path(path.Join(prefix, "/api/v1/label/{name}/values")).Methods("GET").Handler(promRouter)
	router.Path(path.Join(prefix, "/api/v1/series")).Methods("GET", "POST", "DELETE").Handler(promRouter)
	router.Path(path.Join(prefix, "/api/v1/metadata")).Methods("GET").Handler(promRouter)

	// TODO(gotjosh): This custom handler is temporary until we're able to vendor the changes in:
	// https://github.com/prometheus/prometheus/pull/7125/files
	router.Path(path.Join(legacyPrefix, "/api/v1/metadata")).Handler(querier.MetadataHandler(distributor))
	router.Path(path.Join(legacyPrefix, "/api/v1/read")).Handler(querier.RemoteReadHandler(queryable, logger))
	router.Path(path.Join(legacyPrefix, "/api/v1/read")).Methods("POST").Handler(legacyPromRouter)
	router.Path(path.Join(legacyPrefix, "/api/v1/query")).Methods("GET", "POST").Handler(legacyPromRouter)
	router.Path(path.Join(legacyPrefix, "/api/v1/query_range")).Methods("GET", "POST").Handler(legacyPromRouter)
	router.Path(path.Join(legacyPrefix, "/api/v1/query_exemplars")).Methods("GET", "POST").Handler(legacyPromRouter)
	router.Path(path.Join(legacyPrefix, "/api/v1/labels")).Methods("GET", "POST").Handler(legacyPromRouter)
	router.Path(path.Join(legacyPrefix, "/api/v1/label/{name}/values")).Methods("GET").Handler(legacyPromRouter)
	router.Path(path.Join(legacyPrefix, "/api/v1/series")).Methods("GET", "POST", "DELETE").Handler(legacyPromRouter)
	router.Path(path.Join(legacyPrefix, "/api/v1/metadata")).Methods("GET").Handler(legacyPromRouter)

	// Track execution time.
	return stats.NewWallTimeMiddleware().Wrap(router)
}
