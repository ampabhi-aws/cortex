package memory

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/cortexproject/cortex/pkg/configs/userconfig"
)

// TestConcurrentReadWrite exercises the memory DB from many goroutines so that
// go test -race catches any unsynchronised map read/write regression.
func TestConcurrentReadWrite(t *testing.T) {
	d, err := New("memory://", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	cfg := userconfig.Config{
		RulesConfig: userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
	}

	const workers = 32
	const iters = 100

	var wg sync.WaitGroup
	wg.Add(workers * 4)

	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = d.SetConfig(ctx, "set-user-"+strconv.Itoa(w), cfg)
			}
		}()
	}

	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				userID := "rules-user-" + strconv.Itoa(w)
				_, _ = d.SetRulesConfig(ctx, userID,
					userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2},
					userconfig.RulesConfig{FormatVersion: userconfig.RuleFormatV2})
			}
		}()
	}

	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_, _ = d.GetAllConfigs(ctx)
				_, _ = d.GetConfigs(ctx, 0)
				_, _ = d.GetAllRulesConfigs(ctx)
				_, _ = d.GetRulesConfigs(ctx, 0)
			}
		}()
	}

	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				userID := "set-user-" + strconv.Itoa(w)
				_, _ = d.GetConfig(ctx, userID)
				_, _ = d.GetRulesConfig(ctx, userID)
			}
		}()
	}

	wg.Wait()

	all, err := d.GetAllConfigs(ctx)
	if err != nil {
		t.Fatalf("GetAllConfigs: %v", err)
	}
	before := len(all)
	all["sentinel-key"] = userconfig.View{}
	after, err := d.GetAllConfigs(ctx)
	if err != nil {
		t.Fatalf("GetAllConfigs: %v", err)
	}
	if len(after) != before {
		t.Fatalf("GetAllConfigs must return a copy; got live map (before=%d after=%d)", before, len(after))
	}
}
