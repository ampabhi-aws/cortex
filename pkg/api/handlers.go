package api

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
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

			actualCfgObj, err := util.YAMLMarshalUnmarshal(actualCfg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			diff, err := util.DiffConfig(defaultCfgObj, actualCfgObj)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			output = diff

		case "defaults":
			defaultCfgObj, err := util.YAMLMarshalUnmarshal(defaultCfg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			output = defaultCfgObj
		default:
			actualCfgObj, err := util.YAMLMarshalUnmarshal(actualCfg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			output = actualCfgObj
		}

		// Scrub any secrets that are not already handled by the type-based
		// flagext.Secret redaction (e.g. URL-shaped options that can embed
		// userinfo credentials) before serving the response.
		if m, ok := output.(map[interface{}]interface{}); ok {
			redactConfigURLs(m)
		}

		util.WriteYAMLResponse(w, output)
	}
}

// urlFieldsToRedact is an allowlist of YAML field names whose string values
// may contain a URL with embedded userinfo credentials (user:password@host).
// Any such userinfo is stripped before the /config endpoint serializes the
// value so that credentials pasted into these fields are not leaked.
var urlFieldsToRedact = map[string]struct{}{
	"uri":              {}, // configs.database.uri
	"alertmanager_url": {}, // ruler.alertmanager_url
}

// redactConfigURLs walks the YAML-unmarshalled config tree and strips any
// embedded userinfo from values whose keys are in urlFieldsToRedact.
func redactConfigURLs(node map[interface{}]interface{}) {
	for k, v := range node {
		switch value := v.(type) {
		case map[interface{}]interface{}:
			redactConfigURLs(value)
		case []interface{}:
			for _, item := range value {
				if child, ok := item.(map[interface{}]interface{}); ok {
					redactConfigURLs(child)
				}
			}
		case string:
			keyStr, ok := k.(string)
			if !ok {
				continue
			}
			if _, redact := urlFieldsToRedact[keyStr]; !redact {
				continue
			}
			node[k] = stripURLUserinfo(value)
		}
	}
}

// stripURLUserinfo removes any userinfo (user:password) from a URL string.
// If the input is empty, is not a parseable URL, or has no userinfo, it is
// returned unchanged (with the password masked if one was present but the
// URL could not be re-serialized).
func stripURLUserinfo(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPassword := u.User.Password(); !hasPassword && u.User.Username() == "" {
		return raw
	}
	// Preserve the username (not sensitive on its own) but drop the password.
	if username := u.User.Username(); username != "" {
		u.User = url.User(username)
	} else {
		u.User = nil
	}
	return u.String()
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
