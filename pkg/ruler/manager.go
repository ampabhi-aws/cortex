package ruler

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	ot "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/notifier"
	promRules "github.com/prometheus/prometheus/rules"
	"github.com/weaveworks/common/user"
	"golang.org/x/net/context/ctxhttp"

	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
)

type DefaultMultiTenantManager struct {
	cfg            Config
	notifierCfg    *config.Config
	managerFactory ManagerFactory

	mapper *mapper

	// Structs for holding per-user Prometheus rules Managers
	// and a corresponding metrics struct.
	// userManagerMtx guards short critical sections that read/modify the
	// userManagers map only. It MUST NOT be held across blocking per-tenant
	// work (notably mapper.MapRules and manager.Update), otherwise one tenant
	// can stall rule sync and the rules/alerts API for all other tenants.
	userManagerMtx     sync.Mutex
	userManagers       map[string]RulesManager
	userManagerMetrics *ManagerMetrics

	// userSyncMtxs holds per-user mutexes used to serialize concurrent
	// syncRulesToManager calls for the same tenant without blocking other
	// tenants. The map itself is guarded by userSyncMtxsMtx.
	userSyncMtxsMtx sync.Mutex
	userSyncMtxs    map[string]*sync.Mutex

	// Per-user notifiers with separate queues.
	notifiersMtx sync.Mutex
	notifiers    map[string]*rulerNotifier

	managersTotal                 prometheus.Gauge
	lastReloadSuccessful          *prometheus.GaugeVec
	lastReloadSuccessfulTimestamp *prometheus.GaugeVec
	configUpdatesTotal            *prometheus.CounterVec
	registry                      prometheus.Registerer
	logger                        log.Logger
}

func NewDefaultMultiTenantManager(cfg Config, managerFactory ManagerFactory, reg prometheus.Registerer, logger log.Logger) (*DefaultMultiTenantManager, error) {
	ncfg, err := buildNotifierConfig(&cfg)
	if err != nil {
		return nil, err
	}

	userManagerMetrics := NewManagerMetrics(cfg.DisableRuleGroupLabel)
	if reg != nil {
		reg.MustRegister(userManagerMetrics)
	}

	return &DefaultMultiTenantManager{
		cfg:                cfg,
		notifierCfg:        ncfg,
		managerFactory:     managerFactory,
		notifiers:          map[string]*rulerNotifier{},
		mapper:             newMapper(cfg.RulePath, logger),
		userManagers:       map[string]RulesManager{},
		userSyncMtxs:       map[string]*sync.Mutex{},
		userManagerMetrics: userManagerMetrics,
		managersTotal: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Namespace: "cortex",
			Name:      "ruler_managers_total",
			Help:      "Total number of managers registered and running in the ruler",
		}),
		lastReloadSuccessful: promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "cortex",
			Name:      "ruler_config_last_reload_successful",
			Help:      "Boolean set to 1 whenever the last configuration reload attempt was successful.",
		}, []string{"user"}),
		lastReloadSuccessfulTimestamp: promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "cortex",
			Name:      "ruler_config_last_reload_successful_seconds",
			Help:      "Timestamp of the last successful configuration reload.",
		}, []string{"user"}),
		configUpdatesTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Namespace: "cortex",
			Name:      "ruler_config_updates_total",
			Help:      "Total number of config updates triggered by a user",
		}, []string{"user"}),
		registry: reg,
		logger:   logger,
	}, nil
}

func (r *DefaultMultiTenantManager) SyncRuleGroups(ctx context.Context, ruleGroups map[string]rulespb.RuleGroupList) {
	// Per-user locks ensure that concurrent SyncRuleGroups calls do not race
	// on the same tenant, while allowing different tenants' syncs to proceed
	// independently. The process-wide userManagerMtx is only taken for short
	// critical sections that read/modify the userManagers map, so one slow
	// tenant can no longer stall rule sync or the rules/alerts API for
	// others.
	for userID, ruleGroup := range ruleGroups {
		r.syncRulesToManager(ctx, userID, ruleGroup)
	}

	// Snapshot the current set of managed users under the short lock, so we
	// can detect users that no longer have rule groups without holding the
	// mutex across the blocking Stop/cleanup calls.
	r.userManagerMtx.Lock()
	existing := make([]string, 0, len(r.userManagers))
	for userID := range r.userManagers {
		existing = append(existing, userID)
	}
	r.userManagerMtx.Unlock()

	// Check for deleted users and remove them.
	for _, userID := range existing {
		if _, stillPresent := ruleGroups[userID]; stillPresent {
			continue
		}

		// Serialize per-user state transitions with any concurrent sync for
		// the same tenant.
		userMtx := r.getUserSyncMtx(userID)
		userMtx.Lock()

		r.userManagerMtx.Lock()
		mngr, exists := r.userManagers[userID]
		if exists {
			delete(r.userManagers, userID)
		}
		r.userManagerMtx.Unlock()

		if exists {
			go mngr.Stop()

			r.removeNotifier(userID)
			r.mapper.cleanupUser(userID)
			r.lastReloadSuccessful.DeleteLabelValues(userID)
			r.lastReloadSuccessfulTimestamp.DeleteLabelValues(userID)
			r.configUpdatesTotal.DeleteLabelValues(userID)
			r.userManagerMetrics.RemoveUserRegistry(userID)
			level.Info(r.logger).Log("msg", "deleted rule manager and local rule files", "user", userID)
		}

		userMtx.Unlock()
	}

	r.userManagerMtx.Lock()
	total := len(r.userManagers)
	r.userManagerMtx.Unlock()
	r.managersTotal.Set(float64(total))
}

// getUserSyncMtx returns the per-user mutex used to serialize
// syncRulesToManager and deletion for a single tenant. Entries are retained
// for the lifetime of the DefaultMultiTenantManager; the map's size is
// bounded by the number of tenants that have ever been seen on this ruler and
// each entry is a trivially small sync.Mutex.
func (r *DefaultMultiTenantManager) getUserSyncMtx(userID string) *sync.Mutex {
	r.userSyncMtxsMtx.Lock()
	defer r.userSyncMtxsMtx.Unlock()
	m, ok := r.userSyncMtxs[userID]
	if !ok {
		m = &sync.Mutex{}
		r.userSyncMtxs[userID] = m
	}
	return m
}

// syncRulesToManager maps the rule files to disk, detects any changes and will create/update the
// the users Prometheus Rules Manager.
//
// The process-wide userManagerMtx is only acquired for the brief read/write of
// the userManagers map. Blocking operations (mapper.MapRules and
// manager.Update, which waits for in-flight rule-group evaluations to
// terminate) are performed outside that mutex so one tenant cannot stall rule
// sync or the rules/alerts API for other tenants. Concurrent calls for the
// same tenant are serialized via a per-user mutex acquired by the caller.
func (r *DefaultMultiTenantManager) syncRulesToManager(ctx context.Context, user string, groups rulespb.RuleGroupList) {
	userMtx := r.getUserSyncMtx(user)
	userMtx.Lock()
	defer userMtx.Unlock()

	// Map the files to disk and return the file names to be passed to the users manager if they
	// have been updated. Done outside userManagerMtx: this is per-tenant I/O.
	update, files, err := r.mapper.MapRules(user, groups.Formatted())
	if err != nil {
		r.lastReloadSuccessful.WithLabelValues(user).Set(0)
		level.Error(r.logger).Log("msg", "unable to map rule files", "user", user, "err", err)
		return
	}

	r.userManagerMtx.Lock()
	manager, exists := r.userManagers[user]
	r.userManagerMtx.Unlock()

	if !exists || update {
		level.Debug(r.logger).Log("msg", "updating rules", "user", user)
		r.configUpdatesTotal.WithLabelValues(user).Inc()
		if !exists {
			level.Debug(r.logger).Log("msg", "creating rule manager for user", "user", user)
			manager, err = r.newManager(ctx, user)
			if err != nil {
				r.lastReloadSuccessful.WithLabelValues(user).Set(0)
				level.Error(r.logger).Log("msg", "unable to create rule manager", "user", user, "err", err)
				return
			}
			// manager.Run() starts running the manager and blocks until Stop() is called.
			// Hence run it as another goroutine.
			go manager.Run()

			r.userManagerMtx.Lock()
			r.userManagers[user] = manager
			r.userManagerMtx.Unlock()
		}
		// manager.Update can block until the in-flight rule-group evaluation
		// finishes. It is intentionally invoked without holding
		// userManagerMtx so other tenants' sync and GetRules are not blocked.
		err = manager.Update(r.cfg.EvaluationInterval, files, r.cfg.ExternalLabels, r.cfg.ExternalURL.String(), nil)
		if err != nil {
			r.lastReloadSuccessful.WithLabelValues(user).Set(0)
			level.Error(r.logger).Log("msg", "unable to update rule manager", "user", user, "err", err)
			return
		}

		r.lastReloadSuccessful.WithLabelValues(user).Set(1)
		r.lastReloadSuccessfulTimestamp.WithLabelValues(user).SetToCurrentTime()
	}
}

// newManager creates a prometheus rule manager wrapped with a user id
// configured storage, appendable, notifier, and instrumentation
func (r *DefaultMultiTenantManager) newManager(ctx context.Context, userID string) (RulesManager, error) {
	// Create a new Prometheus registry and register it within
	// our metrics struct for the provided user if it doesn't already exist.
	reg := prometheus.NewRegistry()
	r.userManagerMetrics.AddUserRegistry(userID, reg)

	notifier, err := r.getOrCreateNotifier(userID, reg)
	if err != nil {
		return nil, err
	}

	return r.managerFactory(ctx, userID, notifier, r.logger, reg), nil
}

func (r *DefaultMultiTenantManager) removeNotifier(userID string) {
	r.notifiersMtx.Lock()
	defer r.notifiersMtx.Unlock()

	if n, ok := r.notifiers[userID]; ok {
		n.stop()
	}

	delete(r.notifiers, userID)
}

func (r *DefaultMultiTenantManager) getOrCreateNotifier(userID string, userManagerRegistry prometheus.Registerer) (*notifier.Manager, error) {
	r.notifiersMtx.Lock()
	defer r.notifiersMtx.Unlock()

	n, ok := r.notifiers[userID]
	if ok {
		// When there is a stale user, we stop the notifier but do not remove it
		n.run()
		return n.notifier, nil
	}

	n = newRulerNotifier(&notifier.Options{
		QueueCapacity: r.cfg.NotificationQueueCapacity,
		Registerer:    userManagerRegistry,
		Do: func(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
			// Note: The passed-in context comes from the Prometheus notifier
			// and does *not* contain the userID. So it needs to be added to the context
			// here before using the context to inject the userID into the HTTP request.
			ctx = user.InjectOrgID(ctx, userID)
			if err := user.InjectOrgIDIntoHTTPRequest(ctx, req); err != nil {
				return nil, err
			}
			// Jaeger complains the passed-in context has an invalid span ID, so start a new root span
			sp := ot.GlobalTracer().StartSpan("notify", ot.Tag{Key: "organization", Value: userID})
			defer sp.Finish()
			ctx = ot.ContextWithSpan(ctx, sp)
			_ = ot.GlobalTracer().Inject(sp.Context(), ot.HTTPHeaders, ot.HTTPHeadersCarrier(req.Header))
			return ctxhttp.Do(ctx, client, req)
		},
	}, log.With(r.logger, "user", userID))

	n.run()

	// This should never fail, unless there's a programming mistake.
	if err := n.applyConfig(r.notifierCfg); err != nil {
		return nil, err
	}

	r.notifiers[userID] = n
	return n.notifier, nil
}

func (r *DefaultMultiTenantManager) GetRules(userID string) []*promRules.Group {
	var groups []*promRules.Group
	// Snapshot the manager reference under the short lock so RuleGroups is
	// called without holding the process-wide mutex. RulesManager
	// implementations guard their own state.
	r.userManagerMtx.Lock()
	mngr, exists := r.userManagers[userID]
	r.userManagerMtx.Unlock()
	if exists {
		groups = mngr.RuleGroups()
	}
	return groups
}

func (r *DefaultMultiTenantManager) Stop() {
	r.notifiersMtx.Lock()
	for _, n := range r.notifiers {
		n.stop()
	}
	r.notifiersMtx.Unlock()

	level.Info(r.logger).Log("msg", "stopping user managers")
	wg := sync.WaitGroup{}
	// Snapshot the managers under the short lock then invoke Stop and wait
	// outside of it, so unrelated readers of userManagers are not blocked
	// across the (potentially long) shutdown.
	r.userManagerMtx.Lock()
	snapshot := make(map[string]RulesManager, len(r.userManagers))
	for user, manager := range r.userManagers {
		snapshot[user] = manager
	}
	r.userManagerMtx.Unlock()
	for user, manager := range snapshot {
		level.Debug(r.logger).Log("msg", "shutting down user  manager", "user", user)
		wg.Add(1)
		go func(manager RulesManager, user string) {
			manager.Stop()
			wg.Done()
			level.Debug(r.logger).Log("msg", "user manager shut down", "user", user)
		}(manager, user)
	}
	wg.Wait()
	level.Info(r.logger).Log("msg", "all user managers stopped")

	// cleanup user rules directories
	r.mapper.cleanup()
}

func (*DefaultMultiTenantManager) ValidateRuleGroup(g rulefmt.RuleGroup) []error {
	var errs []error

	if g.Name == "" {
		errs = append(errs, errors.New("invalid rules config: rule group name must not be empty"))
		return errs
	}

	if len(g.Rules) == 0 {
		errs = append(errs, fmt.Errorf("invalid rules config: rule group '%s' has no rules", g.Name))
		return errs
	}

	for i, r := range g.Rules {
		for _, err := range r.Validate() {
			var ruleName string
			if r.Alert.Value != "" {
				ruleName = r.Alert.Value
			} else {
				ruleName = r.Record.Value
			}
			errs = append(errs, &rulefmt.Error{
				Group:    g.Name,
				Rule:     i,
				RuleName: ruleName,
				Err:      err,
			})
		}
	}

	return errs
}
