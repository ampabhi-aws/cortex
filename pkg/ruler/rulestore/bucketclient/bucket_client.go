package bucketclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/thanos-io/objstore"
	"golang.org/x/sync/errgroup"

	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
	"github.com/cortexproject/cortex/pkg/ruler/rulestore"
	"github.com/cortexproject/cortex/pkg/storage/bucket"
)

const (
	// The bucket prefix under which all tenants rule groups are stored.
	rulesPrefix = "rules"

	loadConcurrency = 10

	// deleteNamespaceMaxAttempts bounds the number of re-list/delete passes
	// DeleteNamespace performs so a concurrent writer cannot keep the loop
	// running forever while still ensuring the namespace is empty on success.
	deleteNamespaceMaxAttempts = 8
)

var (
	errInvalidRuleGroupKey = errors.New("invalid rule group object key")
	errEmptyUser           = errors.New("empty user")
	errEmptyNamespace      = errors.New("empty namespace")
	errEmptyGroupName      = errors.New("empty group name")
)

// BucketRuleStore is used to support the RuleStore interface against an object storage backend. It is implemented
// using the Thanos objstore.Bucket interface
type BucketRuleStore struct {
	bucket      objstore.Bucket
	cfgProvider bucket.TenantConfigProvider
	logger      log.Logger
}

func NewBucketRuleStore(bkt objstore.Bucket, cfgProvider bucket.TenantConfigProvider, logger log.Logger) *BucketRuleStore {
	return &BucketRuleStore{
		bucket:      bucket.NewPrefixedBucketClient(bkt, rulesPrefix),
		cfgProvider: cfgProvider,
		logger:      logger,
	}
}

// getRuleGroup loads and return a rules group. If existing rule group is supplied, it is Reset and reused. If nil, new RuleGroupDesc is allocated.
func (b *BucketRuleStore) getRuleGroup(ctx context.Context, userID, namespace, groupName string, rg *rulespb.RuleGroupDesc) (*rulespb.RuleGroupDesc, error) {
	userBucket := bucket.NewUserBucketClient(userID, b.bucket, b.cfgProvider)
	objectKey := getRuleGroupObjectKey(namespace, groupName)

	reader, err := userBucket.Get(ctx, objectKey)
	if userBucket.IsObjNotFoundErr(err) {
		level.Debug(b.logger).Log("msg", "rule group does not exist", "user", userID, "key", objectKey)
		return nil, rulestore.ErrGroupNotFound
	}

	if err != nil {
		return nil, errors.Wrapf(err, "failed to get rule group %s", objectKey)
	}
	defer func() { _ = reader.Close() }()

	buf, err := io.ReadAll(reader)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read rule group %s", objectKey)
	}

	if rg == nil {
		rg = &rulespb.RuleGroupDesc{}
	} else {
		rg.Reset()
	}

	err = proto.Unmarshal(buf, rg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal rule group %s", objectKey)
	}

	return rg, nil
}

// ListAllUsers implements rules.RuleStore.
func (b *BucketRuleStore) ListAllUsers(ctx context.Context) ([]string, error) {
	var users []string
	err := b.bucket.Iter(ctx, "", func(user string) error {
		users = append(users, strings.TrimSuffix(user, objstore.DirDelim))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to list users in rule store bucket: %w", err)
	}

	return users, nil
}

// ListAllRuleGroups implements rules.RuleStore.
func (b *BucketRuleStore) ListAllRuleGroups(ctx context.Context) (map[string]rulespb.RuleGroupList, error) {
	out := map[string]rulespb.RuleGroupList{}

	// List rule groups for all tenants.
	err := b.bucket.Iter(ctx, "", func(key string) error {
		userID, namespace, group, err := parseRuleGroupObjectKeyWithUser(key)
		if err != nil {
			level.Warn(b.logger).Log("msg", "invalid rule group object key found while listing rule groups", "key", key, "err", err)

			// Do not fail just because of a spurious item in the bucket.
			return nil
		}

		out[userID] = append(out[userID], &rulespb.RuleGroupDesc{
			User:      userID,
			Namespace: namespace,
			Name:      group,
		})
		return nil
	}, objstore.WithRecursiveIter)

	if err != nil {
		return nil, err
	}

	return out, nil
}

// ListRuleGroupsForUserAndNamespace implements rules.RuleStore.
func (b *BucketRuleStore) ListRuleGroupsForUserAndNamespace(ctx context.Context, userID string, namespace string) (rulespb.RuleGroupList, error) {
	userBucket := bucket.NewUserBucketClient(userID, b.bucket, b.cfgProvider)

	groupList := rulespb.RuleGroupList{}

	// The prefix to list objects depends on whether the namespace has been
	// specified in the request.
	prefix := ""
	if namespace != "" {
		prefix = getNamespacePrefix(namespace)
	}

	err := userBucket.Iter(ctx, prefix, func(key string) error {
		namespace, group, err := parseRuleGroupObjectKey(key)
		if err != nil {
			level.Warn(b.logger).Log("msg", "invalid rule group object key found while listing rule groups", "user", userID, "key", key, "err", err)

			// Do not fail just because of a spurious item in the bucket.
			return nil
		}

		groupList = append(groupList, &rulespb.RuleGroupDesc{
			User:      userID,
			Namespace: namespace,
			Name:      group,
		})
		return nil
	}, objstore.WithRecursiveIter)
	if err != nil {
		return nil, err
	}

	return groupList, nil
}

// LoadRuleGroups implements rules.RuleStore.
//
// A rule-group object that disappears between List and Load (ErrGroupNotFound)
// is treated as an expected concurrent-delete race rather than a hard error:
// the missing descriptors are removed from groupsToLoad so the caller syncs
// the remaining, consistent set. This prevents a single tenant churning
// create/delete calls from freezing rule-group synchronization for every
// other tenant that shares the same ruler replica.
func (b *BucketRuleStore) LoadRuleGroups(ctx context.Context, groupsToLoad map[string]rulespb.RuleGroupList) error {
	ch := make(chan *rulespb.RuleGroupDesc)

	var (
		missingMtx sync.Mutex
		missing   = map[string]map[string]struct{}{}
	)

	recordMissing := func(gr *rulespb.RuleGroupDesc) {
		missingMtx.Lock()
		defer missingMtx.Unlock()
		user := gr.GetUser()
		if _, ok := missing[user]; !ok {
			missing[user] = map[string]struct{}{}
		}
		missing[user][missingKey(gr.GetNamespace(), gr.GetName())] = struct{}{}
	}

	// Given we store one file per rule group. With this, we create a pool of workers that will
	// download all rule groups in parallel. We limit the number of workers to avoid a
	// particular user having too many rule groups rate limiting us with the object storage.
	g, gCtx := errgroup.WithContext(ctx)
	for i := 0; i < loadConcurrency; i++ {
		g.Go(func() error {
			for gr := range ch {
				user, namespace, group := gr.GetUser(), gr.GetNamespace(), gr.GetName()
				if user == "" || namespace == "" || group == "" {
					return fmt.Errorf("invalid rule group: user=%q, namespace=%q, group=%q", user, namespace, group)
				}

				loaded, err := b.getRuleGroup(gCtx, user, namespace, group, gr) // reuse group pointer from the map.
				switch {
				case errors.Is(err, rulestore.ErrGroupNotFound):
					// The group was deleted between List and Load: drop it from
					// this cycle instead of failing the whole multi-tenant batch.
					level.Warn(b.logger).Log("msg", "rule group deleted while loading, skipping",
						"user", user, "namespace", namespace, "group", group)
					recordMissing(gr)
					continue
				case err != nil:
					return errors.Wrapf(err, "get rule group user=%q, namespace=%q, name=%q", user, namespace, group)
				}

				if user != loaded.User || namespace != loaded.Namespace || group != loaded.Name {
					return fmt.Errorf("mismatch between requested rule group and loaded rule group, requested: user=%q, namespace=%q, group=%q, loaded: user=%q, namespace=%q, group=%q", user, namespace, group, loaded.User, loaded.Namespace, loaded.Name)
				}
			}

			return nil
		})
	}

outer:
	for _, gs := range groupsToLoad {
		for _, g := range gs {
			if g == nil {
				continue
			}
			select {
			case <-gCtx.Done():
				break outer
			case ch <- g:
				// ok
			}
		}
	}
	close(ch)

	if err := g.Wait(); err != nil {
		return err
	}

	// Drop descriptors for groups that disappeared mid-load so the caller
	// hands a consistent set to the manager.
	if len(missing) > 0 {
		for user, keys := range missing {
			list, ok := groupsToLoad[user]
			if !ok {
				continue
			}
			filtered := list[:0]
			for _, gr := range list {
				if gr == nil {
					continue
				}
				if _, drop := keys[missingKey(gr.GetNamespace(), gr.GetName())]; drop {
					continue
				}
				filtered = append(filtered, gr)
			}
			if len(filtered) == 0 {
				delete(groupsToLoad, user)
			} else {
				groupsToLoad[user] = filtered
			}
		}
	}

	return nil
}

// missingKey builds a stable, unambiguous key for the (namespace, group) pair.
// We use a NUL byte separator so values that contain the separator cannot
// collide across different (namespace, group) pairs.
func missingKey(namespace, group string) string {
	return namespace + "\x00" + group
}

// GetRuleGroup implements rules.RuleStore.
func (b *BucketRuleStore) GetRuleGroup(ctx context.Context, userID string, namespace string, group string) (*rulespb.RuleGroupDesc, error) {
	return b.getRuleGroup(ctx, userID, namespace, group, nil)
}

// SetRuleGroup implements rules.RuleStore.
func (b *BucketRuleStore) SetRuleGroup(ctx context.Context, userID string, namespace string, group *rulespb.RuleGroupDesc) error {
	userBucket := bucket.NewUserBucketClient(userID, b.bucket, b.cfgProvider)
	data, err := proto.Marshal(group)
	if err != nil {
		return err
	}

	return userBucket.Upload(ctx, getRuleGroupObjectKey(namespace, group.Name), bytes.NewBuffer(data))
}

// DeleteRuleGroup implements rules.RuleStore.
func (b *BucketRuleStore) DeleteRuleGroup(ctx context.Context, userID string, namespace string, group string) error {
	userBucket := bucket.NewUserBucketClient(userID, b.bucket, b.cfgProvider)
	err := userBucket.Delete(ctx, getRuleGroupObjectKey(namespace, group))
	if b.bucket.IsObjNotFoundErr(err) {
		return rulestore.ErrGroupNotFound
	}
	return err
}

// DeleteNamespace implements rules.RuleStore.
//
// DeleteNamespace iterates List+Delete until the namespace is observed empty
// or we hit a bounded attempt cap. The loop tolerates per-object not-found
// errors (another writer may have deleted the same group concurrently) and
// re-lists after each pass so a group created after the initial list is not
// silently retained in the namespace.
func (b *BucketRuleStore) DeleteNamespace(ctx context.Context, userID string, namespace string) error {
	userBucket := bucket.NewUserBucketClient(userID, b.bucket, b.cfgProvider)

	firstPass := true
	for attempt := 0; attempt < deleteNamespaceMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		ruleGroupList, err := b.ListRuleGroupsForUserAndNamespace(ctx, userID, namespace)
		if err != nil {
			return err
		}

		if len(ruleGroupList) == 0 {
			if firstPass {
				return rulestore.ErrGroupNamespaceNotFound
			}
			return nil
		}
		firstPass = false

		for _, rg := range ruleGroupList {
			if err := ctx.Err(); err != nil {
				return err
			}
			objectKey := getRuleGroupObjectKey(rg.Namespace, rg.Name)
			level.Debug(b.logger).Log("msg", "deleting rule group", "user", userID, "namespace", namespace, "key", objectKey)
			if err := userBucket.Delete(ctx, objectKey); err != nil {
				if userBucket.IsObjNotFoundErr(err) {
					// Another caller deleted the same object - treat as idempotent.
					continue
				}
				level.Error(b.logger).Log("msg", "unable to delete rule group from namespace", "user", userID, "namespace", namespace, "key", objectKey, "err", err)
				return err
			}
		}
	}

	return errors.Errorf("namespace %q for user %q was not empty after %d delete passes", namespace, userID, deleteNamespaceMaxAttempts)
}

func getNamespacePrefix(namespace string) string {
	return base64.URLEncoding.EncodeToString([]byte(namespace)) + objstore.DirDelim
}

func getRuleGroupObjectKey(namespace, group string) string {
	return getNamespacePrefix(namespace) + base64.URLEncoding.EncodeToString([]byte(group))
}

// parseRuleGroupObjectKeyWithUser parses a bucket object key in the format "<user>/<namespace>/<rules group>".
func parseRuleGroupObjectKeyWithUser(key string) (user, namespace, group string, err error) {
	parts := strings.SplitN(key, objstore.DirDelim, 2)
	if len(parts) != 2 {
		return "", "", "", errInvalidRuleGroupKey
	}

	user = parts[0]
	if user == "" {
		return "", "", "", errEmptyUser
	}
	namespace, group, err = parseRuleGroupObjectKey(parts[1])
	return
}

// parseRuleGroupObjectKey parses a bucket object key in the format "<namespace>/<rules group>".
func parseRuleGroupObjectKey(key string) (namespace, group string, _ error) {
	parts := strings.Split(key, objstore.DirDelim)
	if len(parts) != 2 {
		return "", "", errInvalidRuleGroupKey
	}

	decodedNamespace, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", err
	}

	if len(decodedNamespace) == 0 {
		return "", "", errEmptyNamespace
	}

	decodedGroup, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}

	if len(decodedGroup) == 0 {
		return "", "", errEmptyGroupName
	}

	return string(decodedNamespace), string(decodedGroup), nil
}
