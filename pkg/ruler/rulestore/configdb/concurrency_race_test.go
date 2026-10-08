package configdb

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

func Test_ConcurrentListAllRuleGroups(t *testing.T) {
	cfgs := map[string]userconfig.VersionedRulesConfig{}
	for i := 0; i < 5; i++ {
		cfgs[fmt.Sprintf("u%d", i)] = userconfig.VersionedRulesConfig{
			ID:        userconfig.ID(10 + i),
			Config:    fakeRuleConfig(),
			DeletedAt: zeroTime,
		}
	}

	store := NewConfigRuleStore(&MockClient{cfgs: cfgs})

	const concurrency = 16
	var wg sync.WaitGroup
	wg.Add(concurrency)

	errs := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := store.ListRuleGroupsForUserAndNamespace(context.Background(), "u1", ""); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
}
